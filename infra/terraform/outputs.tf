output "sensor_public_ip" {
  description = "Point test clients at this address on port 22 (after bootstrap_mode=false)."
  value       = aws_instance.sensor.public_ip
}

output "sensor_instance_id" {
  value = aws_instance.sensor.id
}

output "log_group" {
  value = aws_cloudwatch_log_group.sensors.name
}

output "reader_user" {
  description = "Read-only IAM user for the worker. Create a key: aws iam create-access-key --user-name <this>"
  value       = aws_iam_user.reader.name
}

output "analysis_instance_id" {
  value = var.create_analysis_host ? aws_instance.analysis[0].id : null
}

output "next_steps" {
  value = var.bootstrap_mode ? join("\n", [
    "BOOTSTRAP MODE: decoy port closed, temporary egress open.",
    "1) Wait ~5 min, then check: aws ssm start-session --target ${aws_instance.sensor.id} --region ${var.region}",
    "   sudo tail -n 5 /var/log/voidsentinel-bootstrap.log   (expect 'bootstrap complete')",
    "2) terraform apply -var bootstrap_mode=false   (locks egress, opens decoy to allowed_decoy_cidrs)",
    ]) : join("\n", [
    "LOCKED DOWN: decoy on ${aws_instance.sensor.public_ip}:22 for ${join(", ", var.allowed_decoy_cidrs)}.",
    "Validate egress: aws ssm start-session --target ${aws_instance.sensor.id} --region ${var.region}",
    "                 sudo /opt/voidsentinel/validate_egress.sh",
  ])
}
