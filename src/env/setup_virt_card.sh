#!/usr/bin/bash

set -x -e

bold=$(tput bold)
normal=$(tput sgr0)

CONF_DIR=""
WORK_DIR=""
ENV_PATH=""
PIN='123456'
SOPIN='12345678'
function log() {
  echo -e "${bold}[LOG $(date +"%T")]${normal} $1"
}

while getopts c:w:e: flag
do
    case "$flag" in
        c) CONF_DIR=$OPTARG;;
        w) WORK_DIR=$OPTARG;;
        e) ENV_PATH=$OPTARG;;
        *) echo "Invalid flag is used: $flag";;
    esac
done

export $(grep -v '^#' $ENV_PATH | xargs)

NSSDB=$WORK_DIR/db_$(shuf -i 1-1000 -n 1)
P11LIB='/usr/lib64/pkcs11/libsofthsm2.so'
export SOFTHSM2_CONF="$CONF_DIR/softhsm2.conf" # Should I save previous value of
softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"
mkdir "$NSSDB"
modutil -create -dbdir sql:"$NSSDB" -force
modutil -list -dbdir sql:"$NSSDB" | grep 'library name: p11-kit-proxy.so'
if [ "$?" = "1" ]; then
  modutil -force -add 'SoftHSM PKCS#11' -dbdir sql:"$NSSDB" -libfile $P11LIB
fi

openssl genrsa -out "$USERNAME".key 2048
openssl req -new -nodes -key "$USERNAME".key -reqexts req_exts -config "$CONF_DIR"/req_"$USERNAME".cnf -out "$USERNAME".csr
openssl ca -config "$CONF_DIR"/ca.cnf -batch -notext -keyfile rootCA.key -in "$USERNAME".csr -days 365 -extensions usr_cert -out "$USERNAME".crt

pkcs11-tool --module libsofthsm2.so --slot-index 0 -w "$USERNAME".key -y privkey --label "$USERNAME" -p "$PIN" --set-id 0 -d 0
pkcs11-tool --module libsofthsm2.so --slot-index 0 -w "$USERNAME".crt -y cert --label "$USERNAME" -p "$PIN" --set-id 0 -d 0


systemctl daemon-reload
echo 'disable-in: virt_cacard' >> /usr/share/p11-kit/modules/opensc.module
systemctl restart pcscd virt_cacard
sleep 10

mkdir /home/localuser1/.ssh
ssh-keygen -D /usr/lib64/pkcs11/opensc-pkcs11.so > ~localuser1/.ssh/authorized_keys
chown -R localuser1:localuser1 ~localuser1/.ssh/
chmod 700 ~localuser1/.ssh/
chmod 600 ~localuser1/.ssh/authorized_keys

chmod 600 /etc/sssd/sssd.conf

systemctl stop pcscd.service pcscd.socket virt_cacard sssd
rm -rf /var/lib/sss/{db,mc}/*
systemctl start pcscd sssd

log "End of setup-virt-card script"

exit 0
