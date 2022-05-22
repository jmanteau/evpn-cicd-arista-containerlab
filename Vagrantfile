# -*- mode: ruby -*-
# vi: set ft=ruby :



# Require the AWS provider plugin
#require 'vagrant-aws'

# Install vagrant-disksize to allow resizing the vagrant box disk.
unless Vagrant.has_plugin?("vagrant-disksize")
  raise  Vagrant::Errors::VagrantError.new, "vagrant-disksize plugin is missing. Please install it using 'vagrant plugin install vagrant-disksize' and rerun 'vagrant up'"
end

# Create and configure the AWS instance(s)
Vagrant.configure('2') do |config|

  ######
  ## AWS VM section
  #####
  config.vm.define "awsvm" do |awsvm|
    # Use dummy AWS box
    awsvm.vm.box = 'dummy'
    awsvm.env.enable # Enable vagrant-env (.env)

    # Specify AWS provider configuration
    awsvm.vm.provider :aws do |aws, override|

      #override.vm.synced_folder ".", "/vagrant", disabled: true
      awsvm.vm.synced_folder ".", "/home/ec2-user/evpn-cicd-arista-containerlab", type: "rsync",  rsync__exclude: [".git/","cEOS-lab-*","packer_cache","clab-evpnlab",".vagrant"]

      # Read AWS authentication information from environment variables
      aws.access_key_id = ENV['AWS_ACCESS_KEY_ID']
      aws.secret_access_key = ENV['AWS_SECRET_ACCESS_KEY']
      aws.session_token = ENV['AWS_SESSION_TOKEN']

      # Specify SSH keypair to use
      aws.keypair_name =  ENV['AWS_SSH_KEYPAIR_NAME']
      # Specify region, AMI ID, and security group(s)
      aws.region = ENV['AWS_REGION']
      # Amazon Linux 2 AMI (HVM) - Kernel 5.10
      aws.ami = ENV['AWS_AMI']
      aws.instance_type = ENV['AWS_INSTANCE_TYPE']
      aws.security_groups = [ENV['AWS_SG']]
      aws.subnet_id = ENV['AWS_SUBNET']
      aws.iam_instance_profile_name = ENV['AWS_INSTANCE_PROFILE']

      # Specify username and private key path
      override.ssh.username = 'ec2-user'
      override.ssh.private_key_path = ENV['AWS_SSH_KEY']

      aws.associate_public_ip = true

      aws.tags = {
        'Name' => 'containerlab',
        }

      #aws.user_data = File.read("user_data.txt")
    end
  end

  ######
  ## Local VM section
  #####
  config.vm.define "localvm" do |localvm|
    localvm.env.enable # Enable vagrant-env (.env)
    localvm.vm.box = "generic/debian11"
    localvm.vm.define "evpnlab"
    localvm.disksize.size = '500GB'
    localvm.vm.provider :virtualbox do |domain|
      domain.memory = 8096
      domain.cpus = 2
      #Enable Nesting Virtualization
      domain.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
    end
    localvm.vm.synced_folder ".", "/home/vagrant/evpn-cicd-arista-containerlab"
    localvm.vm.network "forwarded_port", guest: 8000, host: 8000, protocol: "tcp"
    localvm.vm.network "forwarded_port", guest: 3000, host: 3000, protocol: "tcp"
  
    # Enable provisioning with a shell script. Additional provisioners such as
    # Ansible, Chef, Docker, Puppet and Salt are also available. Please see the
    # documentation for more information about their specific syntax and use.
    localvm.vm.provision "shell", inline: <<-SHELL
      export DEBIAN_FRONTEND=noninteractive
      update-alternatives --install /usr/bin/python python /usr/bin/python3 1
      apt-get update
      apt-get install apt-transport-https ca-certificates curl gnupg lsb-release ntp -y
      apt-get install tmux tcpdump tshark python3-pip -y
      curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
      echo   "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      apt-get update
      apt-get install docker-ce docker-ce-cli containerd.io -y
      curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
      chmod +x /usr/local/bin/docker-compose
      bash -c "$(curl -sL https://get-clab.srlinux.dev)" 
      #modprobe 8021q
      #pip3 install ansible ansible-lint -U
      #ntpd -gq
  
      # Renable cgroups v1 for Containerlab
      sed -i "/GRUB_CMDLINE_LINUX=/d" /etc/default/grub
      echo 'GRUB_CMDLINE_LINUX="ipv6.disable_ipv6=1 net.ifnames=0 biosdevname=0 net.ifnames=0 biosdevname=0 systemd.unified_cgroup_hierarchy=false systemd.legacy_systemd_cgroup_controller=false"' >> /etc/default/grub
      update-grub
    
    SHELL
    localvm.vm.provision :reload

  end

end

