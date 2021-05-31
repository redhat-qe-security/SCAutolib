#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -xe

bold=$(tput bold)
normal=$(tput sgr0)


NAME="localuser1"
PIN='123456'
SOPIN='12345678'
export GNUTLS_PIN=$PIN
WORK_DIR="."
ENV_PATH=""

function help() {
  echo -e "Script for settingup the local Certificate Authority and virtual smart card"
  echo -e "\t${bold}-h | --help${normal} this message"
  echo -e "\t${bold}-d | --dir${normal} working durectory. At this directory all necessart file structure woudld be created"
  echo -e "\t${bold}--username${normal} user name for the local user"
  echo -e "\t${bold}--userpasswd${normal} password to be set for the local user"
  echo -e "\t${bold}--pin${normal} PIN to be set for the smart card for a given user in --username"
  echo -e "\t${bold}--conf-dir${normal} directory with all necessary configuraion files"
}

function log() {
  echo -e "${bold}[LOG $(date +"%T")]${normal} $1"
}


while (("$#")); do
  case "$1" in
  -d | --dir)
    WORK_DIR=$2
    shift 2
    ;;
  --env)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      ENV_PATH=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --username)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      NAME=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --userpasswd)
    if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
      USER_PASSWD=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --pin)
    if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
      PIN=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  -h | --help)
    help
    shift
    ;;
  -* | --*=) # unsupported flags
    echo "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  esac
done

RELEASE=$(cat /etc/redhat-release)
if [[ $RELEASE != *"Red Hat Enterprise Linux release 9"*  ]]
then
  dnf -y module enable idm:DL1
  dnf -y copr enable jjelen/vsmartcard
fi

export $(grep -v '^#' $ENV_PATH | xargs)

NSSDB=$WORK_DIR/db

dnf -y install vpcd softhsm python3-pip sssd-tools httpd
yum groupinstall "Smart Card Support" -y

# Configuring softhm2
P11LIB='/usr/lib64/pkcs11/libsofthsm2.so'
pushd $WORK_DIR || exit

mkdir tokens

# Setup local openssl CA
mkdir {certs,crl,newcerts}
touch serial index.txt crlnumber index.txt.attr
echo 01 >serial
openssl genrsa -out rootCA.key 2048

openssl req -batch -config $CONF_DIR/ca.cnf -x509 -new -nodes \
  -key rootCA.key -sha256 -days 10000 -set_serial 0 \
  -extensions v3_ca -out $WORK_DIR/rootCA.crt
openssl ca -config $CONF_DIR/ca.cnf -gencrl -out crl/root.crl

# Setup user and certs on the card
useradd -m $NAME
echo -e "${USER_PASSWD}\n${USER_PASSWD}" | passwd "${NAME}"

openssl genrsa -out ${NAME}.key 2048
openssl req -new -nodes -key ${NAME}.key -reqexts req_exts -config $CONF_DIR/req_${NAME}.cnf -out ${NAME}.csr
openssl ca -config $CONF_DIR/ca.cnf -batch -notext -keyfile rootCA.key -in ${NAME}.csr -days 365 -extensions usr_cert -out ${NAME}.crt

######################################
# Setup SELinux module
######################################
semodule -i $CONF_DIR/virtcacard.cil
cp /usr/lib/systemd/system/pcscd.service /etc/systemd/system/
sed -i 's/ --auto-exit//' /etc/systemd/system/pcscd.service
cp $WORK_DIR/rootCA.crt /etc/sssd/pki/sssd_auth_ca_db.pem

systemctl daemon-reload
systemctl restart pcscd

log "End of setup-ca script"

exit 0
