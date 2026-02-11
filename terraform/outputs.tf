output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.solaradocs.id
}

output "elastic_ip" {
  description = "Elastic IP address"
  value       = aws_eip.solaradocs.public_ip
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.solaradocs.id
}

output "ami_id" {
  description = "AMI used"
  value       = data.aws_ami.ubuntu.id
}
