#! /bin/bash

#
# Exposed ports: 22,3030,3307,8090,8788
# Minimum instance type: t2.xlarge
#


set -e
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

sudo apt update -y
sudo apt install -y build-essential finger git tmux mysql-client
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

if [ -f /etc/apt/keyrings/docker.asc ]; then
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc
fi

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update -y
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl start docker
sudo usermod -aG docker $USER

git config --global url."https://github.com/".insteadOf git@github.com:
if [ ! -d "owid-grapher" ]; then
    git clone https://github.com/owid/owid-grapher.git
fi
cd owid-grapher
cp .env.example-grapher .env
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash
nvm install
npm install -g yarn
make up
