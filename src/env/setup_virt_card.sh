#!/usr/bin/bash

set -e

. "$(dirname $0)/logs.sh" || exit 1

KEY_PATH=""
CERT_PATH=""
ENV_PATH=""
USERNAME="newuser"
CARD_DIR="/root/$USERNAME"
CA_DIR=""
PIN='123456'
LOCAL=0
SOPIN='12345678'


while (("$#")); do
  case "$1" in
  -d | --dir)
    CARD_DIR=$2
    shift 2
    ;;
  --ca)
    CA_DIR=$2
    shift 2
    ;;
  -e | --env)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      ENV_PATH=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  -u|--username)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      USERNAME=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --cert)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      CERT_PATH=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --key)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      KEY_PATH=$2
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

if [ "$ENV_PATH" != "" ]
then
  export $(grep -v '^#' $ENV_PATH | xargs)
fi

NSSDB="$CARD_DIR/db"
P11LIB='/usr/lib64/pkcs11/libsofthsm2.so'
CONF_DIR="$CARD_DIR/conf"

[ ! -d "$CARD_DIR" ] && warn "No card directory provided, creating..." && mkdir -p "$CARD_DIR"
[ ! -d "$CONF_DIR" ] && warn "No configuration directory, creating..." && mkdir -p "$CONF_DIR"

if [[ ! -f "$CONF_DIR/softhsm2.conf" ]]
then
  err "No SoftHSM configuration file"
  exit 1
fi

export SOFTHSM2_CONF="$CONF_DIR/softhsm2.conf" # Should I save previous value of
######################################
# Setup SELinux module
######################################
if [[ $(semodule -l | grep virtcacard) = "0" ]]
then
  log "SELinux module for virt_card is not installed"
  [ -f "$CONF_DIR/virtcacard.cil" ] && err "No $CONF_DIR/virtcacard.cil file"
  semodule -i "$CONF_DIR/virtcacard.cil"
  log "SELinux module for virt_card is installed"
fi

cp /usr/lib/systemd/system/pcscd.service /etc/systemd/system/
sed -i 's/ --auto-exit//' /etc/systemd/system/pcscd.service
systemctl daemon-reload
systemctl restart pcscd
log "pcscd.service is updated"

mkdir -p "$CARD_DIR/tokens" "$NSSDB"
log "Directories for tokens and NSS database are created"

softhsm2-util --init-token --free --label "SC test" --so-pin="$SOPIN" --pin="$PIN"
log "SoftHSM token is initialized with label 'SC test'"

modutil -create -dbdir sql:"$NSSDB" -force
log "NSS database is initialized"

modutil -list -dbdir sql:"$NSSDB" | grep 'library name: p11-kit-proxy.so'
if [ "$?" = "1" ]; then
  modutil -force -add 'SoftHSM PKCS#11' -dbdir sql:"$NSSDB" -libfile $P11LIB
  log "SoftHSM support is added to NSS database"
fi

if [[ "$KEY_PATH" == "$CERT_PATH" ]]
then
  log "No key and certificate are provided"
  CSR_PATH="$CARD_DIR/$USERNAME.csr"
  CERT_PATH="$CARD_DIR/$USERNAME.crt"
  KEY_PATH="$CARD_DIR/$USERNAME.key"

  openssl genrsa -out "$KEY_PATH" 2048
  log "User key is created"
  [ ! -f "$CONF_DIR/req_$USERNAME.cnf" ] && err "No $CONF_DIR/req_$USERNAME.cnf file for user CSR"
  openssl req -new -nodes -key "$KEY_PATH" -reqexts req_exts -config "$CONF_DIR/req_$USERNAME.cnf" -out "$CSR_PATH"
  log "User CSR is created using $CONF_DIR/req_$USERNAME.cnf"
  openssl ca -config "$CA_DIR/conf/ca.cnf" -batch -notext -keyfile "$CA_DIR/rootCA.key" -in "$CSR_PATH" -days 365 -extensions usr_cert -out "$CERT_PATH"
  log "User certificates is created and signed with $CA_DIR/rootCA.key"
  rm -f "$CSR_PATH"
  log "CSR is removed"
fi

pkcs11-tool --module libsofthsm2.so --slot-index 0 -w "$KEY_PATH" -y privkey --label "$USERNAME" -p "$PIN" --set-id 0 -d 0
log "User key $KEY_PATH is added to SoftHSM token"
pkcs11-tool --module libsofthsm2.so --slot-index 0 -w "$CERT_PATH" -y cert --label "$USERNAME" -p "$PIN" --set-id 0 -d 0
log "User certificate $CERT_PATH is added to SoftHSM token"

systemctl daemon-reload
echo 'disable-in: virt_cacard' >> /usr/share/p11-kit/modules/opensc.module
log "opensc.module is updated"

systemctl restart pcscd
log "Waiting 10 seconds"
for _ in {1..10}; do echo -n "."; sleep 1; done
echo

chmod 600 /etc/sssd/sssd.conf

systemctl stop pcscd.service pcscd.socket virt_cacard_"$USERNAME" sssd
rm -rf /var/lib/sss/{db,mc}/*
systemctl start pcscd sssd
log "Directories db,mc are deleted from /var/lib/sss/"

log "End of setup-virt-card script"

exit 0
