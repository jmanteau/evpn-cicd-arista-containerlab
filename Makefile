#help: ## Show this help
#	@egrep '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
.PHONY: help
## -- Help Section --

## This help message
## (can be triggered either by make or make help)
help:
	@printf "Usage\n";

	@awk '{ \
			if ($$0 ~ /^.PHONY: [a-zA-Z\-\_0-9\%]+$$/) { \
				helpCommand = substr($$0, index($$0, ":") + 2); \
				if (helpMessage) { \
					printf "\033[36m%-20s\033[0m %s\n", \
						helpCommand, helpMessage; \
					helpMessage = ""; \
				} \
			} else if ($$0 ~ /^[a-zA-Z\-\_0-9.\%]+:/) { \
				helpCommand = substr($$0, 0, index($$0, ":")); \
				if (helpMessage) { \
					printf "\033[36m%-20s\033[0m %s\n", \
						helpCommand, helpMessage; \
					helpMessage = ""; \
				} \
			} else if ($$0 ~ /^##/) { \
				if (helpMessage) { \
					helpMessage = helpMessage"\n                     "substr($$0, 3); \
				} else { \
					helpMessage = substr($$0, 3); \
				} \
			} else { \
				if (helpMessage) { \
					print "\n                     "helpMessage"\n" \
				} \
				helpMessage = ""; \
			} \
		}' \
		$(MAKEFILE_LIST)


# The Env file contains the variables to adjust and/or the AWS authentication method
# https://lithic.tech/blog/2020-05/makefile-dot-env
ifneq (,$(wildcard ./.env))
    include .env
    export
    ENV_FILE_PARAM = --env-file .env # Used for docker-compose
else
    $(error Env file does not exist! 'cp .env.template .env' and edit accordingly )
endif

# Optionnal Function
ifneq (,$(wildcard ./.env_Makefile))
    include .env_Makefile
    export
endif

# Check that the command exists
cmd-exists-%:
	@hash $(*) > /dev/null 2>&1 || \
		(echo "ERROR: '$(*)' must be installed and available on your PATH."; exit 1)

# Check that the variable exists
guard-%:
	if [ -z '${${*}}' ]; then echo 'ERROR: variable $* not set' && exit 1; fi

## -- Initial Setup --

# Prerequisites: Vagrant, VirtualBox

## Install on the current device the Vagrant plugins needed 
vagrantinstall: cmd-exists-vagrant
	vagrant plugin install vagrant-vbguest 
	vagrant plugin install vagrant-aws-mkubenka --plugin-version "0.7.2.pre.24"
	vagrant plugin install vagrant-reload
	vagrant plugin install vagrant-disksize
	vagrant plugin install vagrant-env


## -- ☁️  AWS Combined Actions --

## 1️⃣️  (Laptop 👨‍💻) 🔓 login on AWS and launch the AWS instance
startupaws: awslogin awsvmup

## 2️⃣️ -1️⃣ (Inside 🎛 ) ⚙️  setup package and python prerequisites on the AWS instance (should be done only once)
aws-install: aws-required python-setup

## 2️⃣️ -2️⃣ (Inside 🎛 ) ⚙️  setup Ansible and image prerequisites on the AWS instance (should be done only once)
setupaws: ansible-setup awsceosimage images tooling-setup

## 3️⃣️  (Inside 🎛 ) ▶️  launch lab on the AWS instance
spinaws: labup 

##    (Laptop 👨‍💻) ⏹️  Stop the AWS instance
haltaws:
	vagrant halt awsvm
	./bin/ssh-config -d -H vagrantlab

##    (Laptop 👨‍💻) 🧨  Destroy the AWS instance
destroyaws: 
	vagrant destroy awsvm -f
	./bin/ssh-config -d -H vagrantlab

## -- 💻️ Local Combined Actions --

## 1️⃣️  (Laptop 👨‍💻) 🎬 build and/or launch the local VM
startuplocal: cmd-exists-vagrant
	vagrant up localvm
	echo "\n " >> ~/.ssh/config
	vagrant ssh-config localvm --host vagrantlab >> $(SSHFILE)
	vagrant ssh localvm

## 2️⃣️  (Inside 🎛 ) ⚙️  setup prerequisites on the local VM (should be done only once)
setuplocal: ansible-setup localceosimage images tooling-setup

## 3️⃣️  (Inside 🎛 ) ▶️  launch lab on the local VM
spinlocal: tinylabup 

##    (Laptop 👨‍💻) ⏹️  Stop the local VM
haltlocal: 
	vagrant halt localvm
	./bin/ssh-config -d -H vagrantlab


##    (Laptop 👨‍💻) 🧨  Destroy the local VM
destroylocal: 
	vagrant destroy localvm -f
	./bin/ssh-config -d -H vagrantlab

##    (Laptop 👨‍💻)   Connect to the local VM
connectlocal: 
	vagrant ssh localvm

## -- AWS Setup --

## Setup the packages needed on the AWS VM
aws-required: 
	# Docker install
	sudo amazon-linux-extras install -y docker
	sudo service docker start
	sudo usermod -a -G docker ec2-user
	sudo chkconfig docker on
	$(eval OS := $(shell uname -s))
	$(eval ARCH := $(shell uname -m))
	wget https://github.com/docker/compose/releases/latest/download/docker-compose-$(OS)-$(ARCH)
	sudo mv docker-compose-$(OS)-$(ARCH) /usr/local/bin/docker-compose
	sudo chmod -v +x /usr/local/bin/docker-compose
	sudo rm -f /usr/bin/docker-compose
	sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
	# exec sg docker "$0 $*"
	# Containerlab install
	sudo yum-config-manager --add-repo=https://yum.fury.io/netdevops/ && echo "gpgcheck=0" | sudo tee -a /etc/yum.repos.d/yum.fury.io_netdevops_.repo
	sudo yum install -y containerlab
	# Utils
	sudo yum install -y git htop zsh 
	# Dev tools
	sudo yum install -y gcc make zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel tk-devel libffi-devel xz-devel openssl11-devel openssl11
	
python-setup:
ifneq ($(wildcard ~/.pyenv/.),)
	@echo "Found Pyenv"
else
	@echo "Did not find Pyenv."
	curl https://pyenv.run | bash 
	~/.pyenv/bin/pyenv install 3.11.1  
	~/.pyenv/bin/pyenv global 3.11 
	sudo update-alternatives --install /usr/bin/python3 python3 ~/.pyenv/shims/python3.11 1
	echo 'export PATH="~/.pyenv/bin:$$PATH"' >> ~/.bash_profile
	echo 'eval "$$(pyenv init --path)"' >> ~/.bash_profile
	echo 'export PATH="~/.pyenv/bin:$$PATH"' >> ~/.bashrc
	echo 'eval "$$(pyenv init --path)"' >> ~/.bashrc
	. ~/.bash_profile
	. ~/.bashrc
	#exec "/bin/bash"
endif

zsh:
	zsh

## Get the public IP of the VM for direct SSH
awsssh: 
	$(eval HOST := $(shell aws ec2 describe-instances --region ${AWS_REGION} --profile ${AWSPROFILE} --filters 'Name=tag:Name,Values=containerlab' --query 'Reservations[*].Instances[*].PublicIpAddress' --output text))
	ssh ec2-user@$(HOST) -i $(AWS_SSH_KEY)  -o 'StrictHostKeyChecking=no'


## AWS VM status
awsvmstatus: 
	aws ec2 describe-instances --region ${AWS_REGION} --profile ${AWSPROFILE} --filters 'Name=tag:Name,Values=containerlab'  --no-cli-pager --output table

## Spin up an AWS instance
awsvmup: cmd-exists-vagrant
	vagrant up awsvm
	echo "\n " >> ~/.ssh/config
	vagrant ssh-config awsvm --host vagrantlab >> $(SSHFILE)
	vagrant ssh awsvm



## -- Lab Setup & Control--

## Clean /var/tmp/agents/core*
cleanceos:
	 $(eval CONTAINERS := $(shell sudo docker ps --format '{{.Names}}' --filter "name=clab-*"))
	$(foreach var,$(CONTAINERS),sudo docker exec $(var) /bin/bash -c 'rm /var/tmp/agents/core.*' ;)


## Copy & Import the CEOS image into the docker registry
awsceosimage:
	aws s3 cp s3://$(AWS_CEOS_S3_BUCKET)/cEOS-lab-$(VERSION_EOS).tar.xz .
	sudo docker import cEOS-lab-$(VERSION_EOS).tar.xz ceosimage:$(VERSION_EOS)

## Copy & Import the CEOS image into the docker registry
localceosimage:
	sudo docker import cEOS-lab-$(VERSION_EOS).tar.xz ceosimage:$(VERSION_EOS)

## Build the container image to use as an end device
images: 
	#ntpd -gq
	cd docker-build && sudo docker build --rm -f Dockerfile_host.alpine -t evpnlab-host:latest .
#	cd docker-build && docker build --rm -f Dockerfile_net -t evpnlab-net:latest .	

## ▶️  Start the tiny lab (3 nodes)
tinylabup: 
	sudo containerlab deploy --topo evpnlab-tiny.yml --reconfigure

## ⏹️  Stop the lab (3 nodes)
tinylabdown: 
	sudo containerlab destroy --topo evpnlab-tiny.yml
	rm -rf clab-evpnlab

tinylabup-alt: 
	sudo containerlab deploy --topo evpnlab-tiny-4.27.yml

tinylabdown-alt: 
	sudo containerlab destroy --topo evpnlab-tiny-4.27.yml
	rm -rf clab-evpnlab


## ▶️  Start the lab
labup: 
	sudo containerlab deploy --topo evpnlab.yml

## ⏹️  Stop the lab
labdown: 
	sudo containerlab destroy --topo evpnlab.yml
	rm -rf clab-evpnlab

## Force clean the lab (needed in case of issues)
labclean: 
	sudo docker stop $(sudo docker ps -a -q) && sudo docker rm $(sudo docker ps -a -q) &&  sudo docker rmi $(sudo docker images -q)

## -- Ansible Section --

## Setup Ansible and Arista AVD Collection
ansible-setup:
	pip3 install ansible
	pip3 install -r https://raw.githubusercontent.com/aristanetworks/ansible-avd/devel/ansible_collections/arista/avd/requirements.txt
	ansible-galaxy collection install arista.avd

## Check that you can communicate with all the nodes
ansible-check: guard-LAB
	cd ansible-$(LAB) && ansible-playbook -i ../clab-evpnlab/ansible-inventory.yml -i group-inventory.yml playbook-facts.yaml

## Create the folder structure needed for AVD
ansible-folder: 
	cd ansible-tinylab && ansible-playbook -i group-inventory.yml -i ../clab-evpnlab/ansible-inventory.yml  playbook-build_folderstructure.yaml

## Create the intented config for the lab
ansible-config: guard-LAB
	cd ansible-tinylab && ansible-playbook -i group-inventory.yml -i ../clab-evpnlab/ansible-inventory.yml  playbook-intendedconfig.yaml -vvv

## Generate, deploy and validate the config for the lab
ansible-deploy: guard-LAB
	cd ansible-tinylab && ansible-playbook -i group-inventory.yml -i ../clab-evpnlab/ansible-inventory.yml  playbook-deploy.yaml

## Configure the host networking
ansible-nethost: guard-LAB
	cd ansible-tinylab && ansible-playbook -i group-inventory.yml -i ../clab-evpnlab/ansible-inventory.yml  playbook-networkhost.yaml


## -- Tooling --

## Tooling setup
tooling-setup:
	cd netbox-interact && pip3 install -r requirements.txt
	# Bugfix while https://github.com/netbox-community/pynetbox/issues/457 and https://github.com/netbox-community/pynetbox/issues/497 not fixed
	wget -q https://raw.githubusercontent.com/Kani999/pynetbox/0b4f33cd2935356821a220e98f0fc7559b3f4262/pynetbox/core/response.py -O ~/.pyenv/versions/3.11.1/lib/python3.11/site-packages/pynetbox/core/response.py
	#wget -q https://raw.githubusercontent.com/netbox-community/pynetbox/75ab3ae2b251605e215dd549c2beacca74baa956/pynetbox/core/response.py -O ~/.pyenv/versions/3.11.1/lib/python3.11/site-packages/pynetbox/core/response.py

## Start Netbox / Gitea / Woodpecker
tooling-start: netbox-start gitea-start woodpecker-start

## Stop Netbox / Gitea / Woodpecker
tooling-stop: netbox-stop gitea-stop woodpecker-stop

## Update Netbox-docker
netbox-update:
	git submodule update --init --recursive

## Start Netbox
netbox-start:
	cp docker-compose.override.yml netbox-docker/docker-compose.override.yml
	cd netbox-docker && sudo docker-compose up -d

## Stop Netbox
netbox-stop:
	cd netbox-docker && sudo docker-compose stop

## URL Netbox:
netbox-url:
	cd netbox-docker && docker-compose port netbox 8080

## Logs Netbox
netbox-logs: 
	cd netbox-docker && sudo docker-compose logs -f

## Populate Netbox
netbox-provision:
	cd netbox-interact && python3 netbox_populate.py

## Reset Netbox Database
netbox-dbreset: netbox-dbreset-raw netbox-start

netbox-dbreset-raw:
	cd netbox-docker && docker-compose stop
	cd netbox-docker && docker-compose rm --stop --force -v postgres
	cd netbox-docker && docker volume rm netbox-docker_netbox-postgres-data
	cd netbox-docker && docker-compose up -d --no-deps postgres
	sleep 2
	cd netbox-docker && docker-compose exec -T postgres sh -c "psql -U netbox -d postgres -c 'DROP DATABASE IF EXISTS netbox;'"
	cd netbox-docker && docker-compose exec -T postgres sh -c "psql -U netbox -d postgres -c 'CREATE DATABASE netbox;'"

## Start Woodpecker
woodpecker-start:
	cd woodpecker && docker-compose up -d $(ENV_FILE_PARAM)

## Stop Woodpecker
woodpecker-stop:
	cd woodpecker && docker-compose stop

## Logs Woodpecker
woodpecker-logs:
	cd woodpecker && docker-compose logs -f

## Start Gitea
gitea-start:
	cd gitea && docker-compose up -d

## Stop Gitea
gitea-stop:
	cd gitea && docker-compose stop

## Logs Gitea
gitea-logs:
	cd gitea && docker-compose logs -f

## -- Nodes Access --

## 🌐 Allow acces to the EOS Cli (valid only with EOS nodes) : cli-$NODENAME
cli-%:
	sudo docker exec -it clab-evpnlab-$* /bin/Cli

## 🔗 Allow acces to the bash shell : bash-$NODENAME
bash-%:
	sudo docker exec -it clab-evpnlab-$*  /bin/bash

## Print Server IPs
ip-host:
	grep -i "ip_address" ansible-$(LAB)/host_vars/clab-evpnlab-h* | cut -d':' -f1,3

## (Laptop 👨‍💻) PCAP Capture on Wireshark on the % node name interface. Works with eth[0-4] (this one is here as example for the help)
pcap-%-eth0:
	ssh vagrantlab "sudo ip netns exec clab-evpnlab-$* tcpdump -U -nni eth0 -w -" | wireshark -k -i -

# PS: easier to list all interfaces than to play with multiples dynamic target in make ... (at least easier to read)
pcap-%-eth1:
	ssh vagrantlab "sudo ip netns exec clab-evpnlab-$* tcpdump -U -nni eth1 -w -" | wireshark -k -i -

pcap-%-eth2:
	ssh vagrantlab "sudo ip netns exec clab-evpnlab-$* tcpdump -U -nni eth2 -w -" | wireshark -k -i -

pcap-%-eth3:
	ssh vagrantlab "sudo ip netns exec clab-evpnlab-$* tcpdump -U -nni eth3 -w -" | wireshark -k -i -

pcap-%-eth4:
	ssh vagrantlab "sudo ip netns exec clab-evpnlab-$* tcpdump -U -nni eth4 -w -" | wireshark -k -i -

# pcap-%-eth4:
# 	ssh vagrant@127.0.0.1 -p 2222 -i .vagrant/machines/localvm/virtualbox/private_key "sudo ip netns exec clab-evpnlab-$* tcpdump -U -nni eth4 -w -" | wireshark -k -i -


