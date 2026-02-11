variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "ebs_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 40
}

variable "key_pair_name" {
  description = "Name of the SSH key pair"
  type        = string
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "solaradocs"
}
