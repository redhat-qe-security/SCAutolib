#!/usr/bin/bash

dnf remove virt_cacard -y
dnf -y copr remove jjelen/vsmartcard
dnf -y module remove idm:DL1
systemctl disablse virt_cacard.service --now
rm -f /etc/systemd/system/virt_cacard.service
rm -f /etc/systemd/system/pcscd.service
systemctl daemon-reload
systemctl restart pcscd
userdel localuser1

semodule -r virtcacard

pip3 uninstall avocado-framework -y
pip3 uninstall pexpect -y
exit 0