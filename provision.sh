#!/bin/sh

apt-get update

apt-get install --yes \
    python3-pip \
    #

ln -sf /usr/bin/python3.5 /usr/bin/python
echo "LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8" > /etc/default/locale

pip3 install -r /vagrant/requirements.txt