# Optional private analysis host: separate VPC, no peering with the sensor VPC,
# NO inbound rules at all. You reach the dashboard with SSM port forwarding.
resource "aws_vpc" "analysis" {
  count                = var.create_analysis_host ? 1 : 0
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.name}-analysis-vpc" }
}

resource "aws_internet_gateway" "analysis" {
  count  = var.create_analysis_host ? 1 : 0
  vpc_id = aws_vpc.analysis[0].id
}

resource "aws_subnet" "analysis" {
  count                   = var.create_analysis_host ? 1 : 0
  vpc_id                  = aws_vpc.analysis[0].id
  cidr_block              = "10.60.1.0/24"
  availability_zone       = local.az
  map_public_ip_on_launch = true # outbound only (image pulls, CloudWatch API); no inbound rules
}

resource "aws_route_table" "analysis" {
  count  = var.create_analysis_host ? 1 : 0
  vpc_id = aws_vpc.analysis[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.analysis[0].id
  }
}

resource "aws_route_table_association" "analysis" {
  count          = var.create_analysis_host ? 1 : 0
  subnet_id      = aws_subnet.analysis[0].id
  route_table_id = aws_route_table.analysis[0].id
}

resource "aws_security_group" "analysis" {
  count       = var.create_analysis_host ? 1 : 0
  name        = "${local.name}-analysis"
  description = "No inbound. Outbound for docker pulls, CloudWatch and SSM."
  vpc_id      = aws_vpc.analysis[0].id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "analysis" {
  count              = var.create_analysis_host ? 1 : 0
  name               = "${local.name}-analysis"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "analysis_ssm" {
  count      = var.create_analysis_host ? 1 : 0
  role       = aws_iam_role.analysis[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "analysis_reader" {
  count      = var.create_analysis_host ? 1 : 0
  role       = aws_iam_role.analysis[0].name
  policy_arn = aws_iam_policy.reader.arn
}

resource "aws_iam_instance_profile" "analysis" {
  count = var.create_analysis_host ? 1 : 0
  name  = "${local.name}-analysis"
  role  = aws_iam_role.analysis[0].name
}

resource "aws_instance" "analysis" {
  count                  = var.create_analysis_host ? 1 : 0
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.analysis_instance_type
  subnet_id              = aws_subnet.analysis[0].id
  vpc_security_group_ids = [aws_security_group.analysis[0].id]
  iam_instance_profile   = aws_iam_instance_profile.analysis[0].name

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2 # lets the worker container reach the instance role
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = <<-EOT
    #!/bin/bash
    set -eux
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker ubuntu
    apt-get install -y git
  EOT

  lifecycle { ignore_changes = [ami, user_data] }
  tags = { Name = "${local.name}-analysis" }
}
