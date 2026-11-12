data "aws_caller_identity" "me" {}
data "aws_availability_zones" "available" { state = "available" }

# Cowrie needs Python >= 3.11, so the sensor uses Ubuntu 24.04 (Python 3.12).
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

locals {
  name           = var.project
  log_group_name = "/${var.project}/sensors"
  az             = data.aws_availability_zones.available.names[0]
  endpoints      = ["logs", "ssm", "ssmmessages", "ec2messages"]
}

# =========================================================== telemetry
resource "aws_cloudwatch_log_group" "sensors" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
}

# Pre-created so the sensor role needs no CreateLogStream permission.
resource "aws_cloudwatch_log_stream" "sensor" {
  name           = var.sensor_name
  log_group_name = aws_cloudwatch_log_group.sensors.name
}

# =========================================================== sensor VPC (isolated)
# Its own VPC with no peering, no transit gateway and no route to anything else.
resource "aws_vpc" "sensor" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true # required for the private interface endpoints
  tags                 = { Name = "${local.name}-sensor-vpc" }
}

resource "aws_internet_gateway" "sensor" {
  vpc_id = aws_vpc.sensor.id
  tags   = { Name = "${local.name}-sensor-igw" }
}

resource "aws_subnet" "sensor" {
  vpc_id                  = aws_vpc.sensor.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = local.az
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-sensor-subnet" }
}

resource "aws_route_table" "sensor" {
  vpc_id = aws_vpc.sensor.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sensor.id
  }
  tags = { Name = "${local.name}-sensor-rt" }
}

resource "aws_route_table_association" "sensor" {
  subnet_id      = aws_subnet.sensor.id
  route_table_id = aws_route_table.sensor.id
}

# Interface endpoints: CloudWatch Logs + Session Manager traffic never leaves AWS,
# so the sensor needs no internet egress once bootstrap is done.
resource "aws_security_group" "endpoints" {
  name        = "${local.name}-endpoints"
  description = "HTTPS from the sensor to the VPC interface endpoints"
  vpc_id      = aws_vpc.sensor.id
  ingress {
    description     = "HTTPS from sensor"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.sensor.id]
  }
}

resource "aws_vpc_endpoint" "iface" {
  for_each            = toset(local.endpoints)
  vpc_id              = aws_vpc.sensor.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.sensor.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${local.name}-${each.key}" }
}

resource "aws_security_group" "sensor" {
  name        = "${local.name}-sensor"
  description = "Decoy SSH in (after bootstrap); egress restricted"
  vpc_id      = aws_vpc.sensor.id
  tags        = { Name = "${local.name}-sensor-sg" }
}

# Decoy listener: opened only after bootstrap, only to the allowed CIDRs.
resource "aws_vpc_security_group_ingress_rule" "decoy" {
  for_each          = var.bootstrap_mode ? toset([]) : toset(var.allowed_decoy_cidrs)
  security_group_id = aws_security_group.sensor.id
  description       = "Decoy SSH (Cowrie via port redirect)"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = each.value
}

# Always: HTTPS to the interface endpoints only.
resource "aws_vpc_security_group_egress_rule" "to_endpoints" {
  security_group_id            = aws_security_group.sensor.id
  description                  = "CloudWatch Logs and SSM via VPC endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints.id
}

# Bootstrap only: package installs. Removed when bootstrap_mode = false.
resource "aws_vpc_security_group_egress_rule" "bootstrap" {
  for_each          = var.bootstrap_mode ? toset(["80", "443"]) : toset([])
  security_group_id = aws_security_group.sensor.id
  description       = "TEMPORARY bootstrap egress (apt, pip, git)"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------- sensor IAM: write to its own stream only
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sensor" {
  name               = "${local.name}-sensor"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "sensor_ssm" {
  role       = aws_iam_role.sensor.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "sensor_logs" {
  name = "write-own-log-stream"
  role = aws_iam_role.sensor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.sensors.arn}:log-stream:${var.sensor_name}"
    }]
  })
}

resource "aws_iam_instance_profile" "sensor" {
  name = "${local.name}-sensor"
  role = aws_iam_role.sensor.name
}

# ---------------- the decoy instance
resource "aws_instance" "sensor" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.sensor_instance_type
  subnet_id              = aws_subnet.sensor.id
  vpc_security_group_ids = [aws_security_group.sensor.id]
  iam_instance_profile   = aws_iam_instance_profile.sensor.name

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 16
    volume_type = "gp3"
    encrypted   = true
  }

  user_data_base64 = base64gzip(templatefile("${path.module}/templates/sensor_user_data.sh.tftpl", {
    cowrie_ref            = var.cowrie_ref
    decoy_hostname        = var.decoy_hostname
    aws_region            = var.region
    log_group             = aws_cloudwatch_log_group.sensors.name
    sensor_name           = var.sensor_name
    collector_b64         = filebase64("${path.module}/../../sensor/collector/collector.py")
    sanitize_b64          = filebase64("${path.module}/../../sensor/collector/sanitize.py")
    validate_b64          = filebase64("${path.module}/../../sensor/scripts/validate_egress.sh")
    cowrie_service_b64    = filebase64("${path.module}/../../sensor/systemd/cowrie.service")
    collector_service_b64 = filebase64("${path.module}/../../sensor/systemd/voidsentinel-collector.service")
  }))

  # Flipping bootstrap_mode must not rebuild the instance.
  lifecycle {
    ignore_changes = [ami, user_data_base64]
  }

  depends_on = [aws_vpc_endpoint.iface, aws_cloudwatch_log_stream.sensor]
  tags       = { Name = "${local.name}-${var.sensor_name}" }
}

# =========================================================== analyst read access
# Read-only access to the sensor log group, for the worker. Create an access key
# with the AWS CLI (see README) so the secret never lands in Terraform state.
data "aws_iam_policy_document" "reader" {
  statement {
    actions   = ["logs:FilterLogEvents", "logs:GetLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.sensors.arn}:*", aws_cloudwatch_log_group.sensors.arn]
  }
}

resource "aws_iam_policy" "reader" {
  name   = "${local.name}-log-reader"
  policy = data.aws_iam_policy_document.reader.json
}

resource "aws_iam_user" "reader" {
  name = "${local.name}-analyst-reader"
}

resource "aws_iam_user_policy_attachment" "reader" {
  user       = aws_iam_user.reader.name
  policy_arn = aws_iam_policy.reader.arn
}

# =========================================================== budget
resource "aws_budgets_budget" "monthly" {
  count        = var.budget_email == "" ? 0 : 1
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }
}
