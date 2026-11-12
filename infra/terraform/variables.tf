variable "region" {
  description = "AWS region (ap-south-1 = Mumbai)."
  type        = string
  default     = "ap-south-1"
}

variable "project" {
  type    = string
  default = "voidsentinel"
}

variable "sensor_name" {
  description = "Name of this decoy sensor; becomes the CloudWatch log stream."
  type        = string
  default     = "sensor-01"
}

variable "allowed_decoy_cidrs" {
  description = "Who may reach the decoy on port 22. Start with your own IP (x.x.x.x/32); widen to [\"0.0.0.0/0\"] only after validating egress."
  type        = list(string)
}

variable "bootstrap_mode" {
  description = "true on first apply: allows outbound HTTP(S) so the sensor can install packages, and keeps port 22 closed. Set false afterwards to lock egress down and open the decoy."
  type        = bool
  default     = true
}

variable "sensor_instance_type" {
  type    = string
  default = "t3.small"
}

variable "cowrie_ref" {
  description = "Cowrie git tag or branch to install."
  type        = string
  default     = "v3.1.6"
}

variable "decoy_hostname" {
  description = "Hostname the emulated shell presents."
  type        = string
  default     = "build-07"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "create_analysis_host" {
  description = "Also create a private analysis EC2 (no inbound ports; reach the dashboard through SSM port forwarding)."
  type        = bool
  default     = false
}

variable "analysis_instance_type" {
  type    = string
  default = "t3.small"
}

variable "budget_limit_usd" {
  description = "Monthly AWS Budget limit. Set budget_email to enable."
  type        = number
  default     = 60
}

variable "budget_email" {
  description = "Email for budget alerts (empty = no budget created)."
  type        = string
  default     = ""
}
