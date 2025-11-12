provider "aws" {
  region = var.region
}
 
# Security Group
resource "aws_security_group" "app_sg" {
  name        = "knock-at-door-sg"
  description = "Allow SSH, HTTP and app port"
  vpc_id      = data.aws_vpc.default.id
 
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
 
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 
  ingress {
    description = "Flask app"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
 
  tags = {
    Name = "knock-at-door-sg"
  }
}
 
# Find default VPC
data "aws_vpc" "selected"{
    filter {
      name = "is-default"
      values = ["true"]
    }
}
 
# Find default subnets (first two)
data "aws_subnets" "selected" {
    filter {
      name = "vpc-id"
      values = [data.aws_vpc.default.id]
    }
}
 
# IAM role & instance profile (optional; if you want instance permissions)
resource "aws_iam_role" "ec2_role" {
  name = "knock_at_door_ec2_role"
 
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_policy.json
}
 
data "aws_iam_policy_document" "ec2_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}
 
resource "aws_iam_role_policy_attachment" "ssm_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
 
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "knock_at_door_instance_profile"
  role = aws_iam_role.ec2_role.name
}
 
# Look up latest Amazon Linux 2023 AMI
data "aws_ami" "amzn2023" {
    most_recent = true
    owners      = ["amazon"]
  
    filter {
        name   = "name"
        values = ["al2023-ami-*-x86_64"]
    }
}
 
# EC2 instance
resource "aws_instance" "app" {
    ami                    = data.aws_ami.amzn2023.id
    instance_type          = var.instance_type
    key_name               = var.key_name
    vpc_security_group_ids = [aws_security_group.app_sg.id]
    iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

    user_data = <<-EOF
                #!/bin/bash
                yum update -y
                yum install -y python3 git
                yum install -y python3-pip
    
                cd /home/ec2-user
    
                # clone your repo
                if [ -d "${var.app_dir}" ]; then
                    cd ${var.app_dir}
                    git pull origin main || true
                else
                    git clone ${var.github_repo} ${var.app_dir}
                fi
    
                cd ${var.app_dir}/frontend-flask
    
                pip3 install --user -r requirements.txt
    
                # Create systemd service to run Flask via gunicorn
                cat > /etc/systemd/system/knockatdoor.service << SERVICE
                [Unit]
                Description=KnockAtDoor Flask App
                After=network.target
    
                [Service]
                User=ec2-user
                WorkingDirectory=${var.app_dir}/frontend-flask
                ExecStart=/home/ec2-user/.local/bin/gunicorn -b 0.0.0.0:5000 app:app
                Restart=always
    
                [Install]
                WantedBy=multi-user.target
                SERVICE
    
                systemctl daemon-reload
                systemctl enable knockatdoor.service
                systemctl start knockatdoor.service
                EOF
 
  tags = {
    Name = "knock-at-door-instance"
  }
}
 
# Create ALB
resource "aws_lb" "alb" {
  name               = "knock-at-door-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.app_sg.id]
  subnets            = data.aws_subnets.default.ids
  enable_deletion_protection = false
  tags = {
    Name = "knock-at-door-alb"
  }
}
 
# Target group for Flask on port 5000
resource "aws_lb_target_group" "flask_tg" {
  name     = "flask-tg"
  port     = 5000
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id
  health_check {
    interval            = 30
    path                = "/"
    matcher             = "200,302"
    protocol            = "HTTP"
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}
 
# Register EC2 instance with target group
resource "aws_lb_target_group_attachment" "flask_attach" {
  target_group_arn = aws_lb_target_group.flask_tg.arn
  target_id        = aws_instance.app.id
  port             = 5000
}
 
# Listener
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"
 
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.flask_tg.arn
  }
  }
