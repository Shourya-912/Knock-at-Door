terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}
 
variable "region" {
  type    = string
  default = "us-east-1"
}
 
variable "instance_type" {
  type    = string
  default = "t3.micro"
}
 
variable "key_name" {
  description = "Existing EC2 key pair name in this account/region"
  type        = string
  default = "shourya_kd"
}
 
variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH (your IP)"
  type        = string
  default     = "0.0.0.0/0"
}
 
variable "github_repo" {
  description = "HTTPS clone URL for your frontend repo (use your repo)"
  type        = string
  default     = "https://github.com/Shourya-912/Knock-at-Door.git"
}
 
variable "app_dir" {
  description = "Path on instance where app will be cloned"
  type        = string
  default     = "/home/ec2-user/Knock-at-Door"
}