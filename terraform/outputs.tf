output "alb_dns_name" {
  description = "ALB DNS"
  value       = aws_lb.alb.dns_name
}
 
output "instance_public_ip" {
  value = aws_instance.app.public_ip
}