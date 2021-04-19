#!/usr/bin/bash

set -x -e

bold=$(tput bold)
normal=$(tput sgr0)

CONF=""
VIRT=""

function log() {
  echo -e "${bold}[LOG $(date +"%T")]${normal} $1"
}

while getopts c:w: flag
do
    case "$flag" in
        c) CONF=$OPTARG;;
        w) VIRT=$OPTARG;;
        *) echo "Invalid flag is used: $flag";;
    esac
done

dnf -y install virt_cacard
cp $CONF/virt_cacard.service /etc/systemd/system/virt_cacard.service
sed -i "s,<TESTDIR>,$VIRT,g" /etc/systemd/system/virt_cacard.service
systemctl daemon-reload
echo 'disable-in: virt_cacard' >> /usr/share/p11-kit/modules/opensc.module
systemctl restart pcscd virt_cacard
sleep 10

mkdir /home/localuser1/.ssh
ssh-keygen -D /usr/lib64/pkcs11/opensc-pkcs11.so > ~localuser1/.ssh/authorized_keys
chown -R localuser1:localuser1 ~localuser1/.ssh/
chmod 700 ~localuser1/.ssh/
chmod 600 ~localuser1/.ssh/authorized_keys

cp $CONF/sssd.conf /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
cat $VIRT/rootCA.crt > /etc/sssd/pki/sssd_auth_ca_db.pem

systemctl stop pcscd.service pcscd.socket virt_cacard sssd
rm -rf /var/lib/sss/{db,mc}/*
systemctl start pcscd sssd

log "End of setup-virt-card script"

exit 0
