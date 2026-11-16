output "public_ip" {
  description = "Elastic IP of the box. Point the DNS A record of the control server host at it."
  value       = aws_eip.this.public_ip
}

output "instance_id" {
  description = "EC2 instance id."
  value       = aws_instance.this.id
}

output "ssh" {
  description = "SSH command. Works only from an address inside admin_cidr."
  value       = "ssh ubuntu@${aws_eip.this.public_ip}"
}
