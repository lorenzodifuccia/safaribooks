# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/xenial64"

  $HOSTNAME="safaribooks"
  $MEM = 1024
  $CPU = 1

  config.vm.hostname = $HOSTNAME
  config.vm.box_check_update = false

  config.vm.provider "libvirt" do |dm, override|
    dm.memory = $MEM
    dm.cpus = $CPU
  end

  config.vm.provider "virtualbox" do |vb|
    vb.name = $HOSTNAME
    vb.customize ["modifyvm", :id, "--name", $HOSTNAME]
    vb.memory = $MEM
    vb.cpus = $CPU
  end

  config.ssh.forward_agent = true

  config.vm.provision "shell" do |s|
    s.path = "provision.sh"
  end
end
