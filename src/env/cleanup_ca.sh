#!/usr/bin/bash

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

pip3 uninstall avocado-framework -y
pip3 uninstall pexpect -y

exit 0