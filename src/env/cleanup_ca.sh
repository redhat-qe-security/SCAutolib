#!/usr/bin/bash

set -xe
NAME=localuser1

dnf -y module disable idm:DL1
dnf remove virt_cacard vpcd -y
dnf -y copr remove jjelen/vsmartcard
systemctl disable virt_cacard.service --now

userdel -r ${NAME}

semodule -r virtcacard

rm -f /etc/systemd/system/virt_cacard.service
rm -f /etc/systemd/system/pcscd.service

systemctl daemon-reload
systemctl restart pcscd

pip3 uninstall avocado-framework pexpect click pyyaml \
avocado-framework-plugin-varianter-yaml-to-mux -y


exit 0
