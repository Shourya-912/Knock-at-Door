#!/bin/bash
 
# echo "==== Cloning your repo ===="
# git clone https://github.com/Shourya-912/Knock-at-Door.git

# echo "==== changing directory ===="
# cd Knock-at-Door/frontend-flask
 
echo "==== Installing python3 ===="
sudo yum install python3-pip -y

echo "==== Installing Flask ===="
pip3 install flask flask-cors

echo "==== Installing flask_pymongo ===="
pip3 install flask_pymongo

echo "==== Installing bcrypt and pymongo ===="
pip3 install pymongo flask-bcrypt

echo "==== running App ===="
Python3 app.py
