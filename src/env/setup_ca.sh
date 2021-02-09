#!/usr/bin/bash

DIR=''

while getopts d: flag
do
    case "${flag}" in
        d) DIR=${OPTARG};;
    esac
done

dnf -y module enable idm:DL1
dnf -y copr enable jjelen/vsmartcard
dnf -y install virt_cacard vpcd softhsm
dnf install  -y


SOPIN='12345678'
PIN='123456'
export GNUTLS_PIN=$PIN
GENERATE_KEYS=1
PKCS11_TOOL='pkcs11-tool'
NSSDB=$DIR/db
CONF=$DIR/conf
NAME=localuser1


if [[ ! -f "$CONF/softhsm2.conf" ]]; 
then 
    echo "File $CONF/softhsm2.conf does not exist"
    exit 1
elif [[ ! -f "$CONF/ca.cnf"]];
then
    echo "File $CONF/ca.cnf does not exist"
    exit 
elif [[ ! -f "$CONF/req_${NAME}.cnf" ]]
then
    echo "File $CONF/req_${NAME}.cnf does not exist"
    exit 1
elif [[ ! -f "$CONF/virtcacard.cil" ]]
then
    echo "File $CONF/virtcacard.cil does not exist"
    exit 1
elif [[ ! -f "$CONF/virt_cacard.service" ]]
then
    echo "File $CONF/virt_cacard.service does not exist"
    exit 1
elif [[ ! -f "$CONF/sssd.conf" ]]
then
    echo "File $CONF/sssd.conf does not exist"
    exit 1


# Configurting softhm2
P11LIB='/usr/lib64/pkcs11/libsofthsm2.so'
sed -i "s,<TESTDIR>,$DIR,g" $CONF/softhsm2.conf

mkdir $DIR/tokens
export SOFTHSM2_CONF="$CONF/softhsm2.conf" # Should I save previous value of 
softhsm2-util --init-token --slot 0 --label 'SC test' --so-pin="$SOPIN" --pin="$PIN"


# Creating NSS database
mkdir $NSSDB
modutil -create -dbdir sql:$NSSDB -force
modutil -list -dbdir sql:$NSSDB | grep 'library name: p11-kit-proxy.so'
if [ "$?" = "1" ]; then 
    modutil -force -add 'SoftHSM PKCS#11' -dbdir sql:$NSSDB -libfile $P11LIB
fi

# Setup local openssl CA
mkdir {certs,crl,newcerts}
touch serial index.txt crlnumber index.txt.attr
echo 01 > serial
openssl genrsa -out rootCA.key 2048

openssl req -batch -config $CONF/ca.cnf -x509 -new -nodes -key rootCA.key -sha256 -days 10000 -set_serial 0 -extensions v3_ca -out $DIR/rootCA.crt
openssl ca -config $CONF/ca.cnf -gencrl -out crl/root.crl

# Setup user and certs on the card
useradd -m $NAME
echo -e '654321\n654321' | passwd localuser1

openssl genrsa -out ${NAME}.key 2048
openssl req -new -nodes -key ${NAME}.key -reqexts req_exts -config $CONF/req_${NAME}.cnf -out ${NAME}.csr
openssl ca -config $CONF/ca.cnf -batch -notext -keyfile rootCA.key -in ${NAME}.csr -days 365 -extensions usr_cert -out ${NAME}.crt

pkcs11-tool --module libsofthsm2.so --slot-index 0 -w ${NAME}.key -y privkey --label ${NAME} -p $PIN --set-id 0 -d 0
pkcs11-tool --module libsofthsm2.so --slot-index 0 -w ${NAME}.crt -y cert --label ${NAME} -p $PIN --set-id 0 -d 0

semodule -i $CONF/virtcacard.cil
cp /usr/lib/systemd/system/pcscd.service /etc/systemd/system/
sed -i 's/ --auto-exit//' /etc/systemd/system/pcscd.service
systemctl daemon-reload
systemctl restart pcscd

cp $CONF/virt_cacard.service /etc/systemd/system/virt_cacard.service
sed -i "s,{TESTDIR},$DIR,g" /etc/systemd/system/virt_cacard.service
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
cat $DIR/rootCA.crt > /etc/sssd/pki/sssd_auth_ca_db.pem

systemctl stop pcscd.service pcscd.socket virt_cacard sssd
rm -rf /var/lib/sss/{db,mc}/*
systemctl start pcscd sssd

pip3 install avocado-framework pexpect

exit 0