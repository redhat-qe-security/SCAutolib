#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -xe

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

PIN='123456'
SOPIN='12345678'
export GNUTLS_PIN=$PIN
WORK_DIR="."
ENV_PATH=""
CONF_DIR=""

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
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

function err() {
  echo -e "${RED}${bold}[ERROR $(date +"%T")]${normal}${NC} $1"
  exit 1
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
if [[ $RELEASE != *"Red Hat Enterprise Linux release 9"* ]]; then
  dnf -y module enable idm:DL1
  log "idm:DL1 module is enabled"
  dnf -y copr enable jjelen/vsmartcard
  log "Copr repo for virt_cacard is enabled"
fi

if [ "$ENV_PATH" != "" ]; then
  log "Env file $ENV_PATH is used"
  export $(grep -v '^#' $ENV_PATH | xargs)
  echo "ROOT_CRT=$WORK_DIR/rootCA.pem" >> "$ENV_PATH"
fi

CONF_DIR="$WORK_DIR/conf"

[ ! -d "$WORK_DIR" ] && mkdir -p "$WORK_DIR"
log "CA directory is checked"

[ ! -d "$CONF_DIR" ] && mkdir -p "$CONF_DIR"
log "Configuration directory for CA is checked"

[ ! -f "$CONF_DIR/ca.cnf" ] && err "File ca.cnf doesn't exist"
log "Configuration file $CONF_DIR/ca.cnf for CA is fount"

dnf -y install vpcd softhsm python3-pip sssd-tools httpd virt_cacard sssd
yum groupinstall "Smart Card Support" -y
log "Necessary packages are installed"

semodule -i "$CONF_DIR/virtcacard.cil" -v
log "SELinux module for virtual smart card is installed"

pushd "$WORK_DIR" || exit

if [ "$(semodule -l | grep virtcacard)" -ne 0 ]
then
  log "SELinux module for virt_card is not installed"
  if [ -f "$CONF_DIR/virtcacard.cil" ]
  then
    warning "No $CONF_DIR/virtcacard.cil file, creating..."
    echo -e \
    "(allow pcscd_t node_t (tcp_socket (node_bind)));

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t (dir (read search)));" > "$CONF_DIR/virtcacard.cil"
  fi
  semodule -i "$CONF_DIR/virtcacard.cil"
  log "SELinux module for virt_card is installed"
fi

# Setup local openssl CA
mkdir -p {certs,crl,newcerts}
log "Directories for local CA are created"

touch serial index.txt crlnumber index.txt.attr
echo 01 >serial
log "Files for local CA are created"

openssl genrsa -out rootCA.key 2048
log "Key for local CA is created"

openssl req -batch -config "$CONF_DIR"/ca.cnf -x509 -new -nodes \
  -key rootCA.key -sha256 -days 10000 -set_serial 0 \
  -extensions v3_ca -out "$WORK_DIR"/rootCA.crt
log "Certificate for local CA is created"

openssl ca -config "$CONF_DIR"/ca.cnf -gencrl -out crl/root.crl
log "CRL is created"
#cp "$WORK_DIR"/rootCA.crt "$WORK_DIR"/rootCA.pem
cat "$WORK_DIR/rootCA.crt" >> /etc/sssd/pki/sssd_auth_ca_db.pem
log "Root certificate is copied to /etc/sssd/pki/sssd_auth_ca_db.pem"

log "End of setup-ca script"

exit 0
