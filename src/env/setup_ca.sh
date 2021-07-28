#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -e

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

CA_DIR=""
ENV_PATH=""

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
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      CA_DIR=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
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
  -* | --*=) # unsupported flags
    echo "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  esac
done

if [[ "$ENV_PATH" != "" ]]; then
  log "Env file $ENV_PATH is used"
  export $(grep -v '^#' $ENV_PATH | xargs)
fi

if [[ -z "$CA_DIR" ]]
then
  err "No working directory provided. Use --dir <path> parameter for specifying CA dir"
fi

CONF_DIR="$CA_DIR/conf"
# Setup local openssl CA
pushd "$CA_DIR" || exit 1
log "CA directory $CA_DIR"

mkdir -p {certs,crl,newcerts}
log "Directories for local CA are created"

touch serial index.txt crlnumber index.txt.attr
echo 01 >serial
log "Files for local CA are created"

openssl genrsa -out rootCA.key 2048
log "Key for local CA is created"

openssl req -batch -config "$CONF_DIR"/ca.cnf -x509 -new -nodes \
  -key rootCA.key -sha256 -days 10000 -set_serial 0 \
  -extensions v3_ca -out "$CA_DIR"/rootCA.crt
log "Certificate for local CA is created"

openssl ca -config "$CONF_DIR"/ca.cnf -gencrl -out crl/root.crl
log "CRL is created"
cat "$CA_DIR/rootCA.crt" >> /etc/sssd/pki/sssd_auth_ca_db.pem
log "Root certificate is copied to /etc/sssd/pki/sssd_auth_ca_db.pem"

log "CA setup is finished"
