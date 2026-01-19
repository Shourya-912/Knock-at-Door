#!/bin/bash

# echo "==== Installing python ===="
sudo yum install python -y
python --version

# echo "==== Installing git ===="
sudo yum install git -y
git --version

# echo "==== Installing nodejs ===="
sudo yum install nodejs npm -y

# echo "==== Installing nodejs ===="
pip3 install flask

# echo "==== Cloning your repo ===="
# git clone https://github.com/Shourya-912/Knock-at-Door.git

echo "==== installing utils ===="
sudo yum install -y yum-utils
 
echo "==== Adding Terraform Repository ===="
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo

echo "==== installing Terraform ===="
sudo yum -y install terraform
terraform -v
cd terraform

echo "==== running terraform ===="
terraform init
terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars"

# echo "==== Terraform destroy ===="
# terraform destroy -auto-approve

