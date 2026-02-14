# -*- mode: ruby -*-
# Isolated VM for PAM backdoor testing
#
# Usage:
#   vagrant up
#   vagrant ssh -c "sudo /vagrant/install.sh"
#   ssh vagrant@localhost -p 2222   (password: elliot)
#   vagrant destroy -f

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "ssh-door-test"

  # Forward SSH to port 2222
  config.vm.network "forwarded_port", guest: 22, host: 2222

  # Sync current directory
  config.vm.synced_folder ".", "/vagrant"

  # Minimal resources
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "512"
    vb.cpus = 1
    vb.name = "ssh-door-test"
  end

  # Install dependencies
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y openssh-server libpam0g-dev libssl-dev gcc
    systemctl enable ssh
    systemctl start ssh
  SHELL
end
