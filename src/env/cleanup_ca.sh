#!/usr/bin/bash

set -xe
NAME=localuser1

systemctl disable virt_cacard.service --now
dnf remove virt_cacard vpcd -y

RELEASE=$(cat /etc/redhat-release)
if [[ $RELEASE == *"Red Hat Enterprise Linux release 9"*  ]]
then
  dnf remove -y redhat-internal-cert-install-0.1-23.el7.csb.noarch.rpm
  dnf -y copr remove copr.devel.redhat.com/jjelen/vsmartcard rhel-9.dev-x86_64
else
  dnf -y module disable idm:DL1
  dnf -y copr remove jjelen/vsmartcard
fi

userdel -r ${NAME}

semodule -r virtcacard

rm -f /etc/systemd/system/virt_cacard.service
rm -f /etc/systemd/system/pcscd.service

systemctl daemon-reload
systemctl restart pcscd

pip3 uninstall avocado-framework pexpect click pyyaml \
avocado-framework-plugin-varianter-yaml-to-mux -y


exit 0
