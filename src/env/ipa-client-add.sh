#!/usr/bin/bash

set -e

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

ADMIN_PASSWD="SECret.123"
USERNAME="ipa-user"
DIR="/root/$USERNAME"

function log() {
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

while (("$#")); do
  case "$1" in
  -d | --dir)
    DIR=$2
    shift 2
    ;;
  -u | --username)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      USERNAME=$2
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

echo "$ADMIN_PASSWD" | kinit admin
ipa user-add "$USERNAME" --last last --first first --cn "$USERNAME"
log "User '$USERNAME' is added to IPA server"

mkdir -p "$DIR" && pushd "$DIR"
openssl req -new -newkey rsa:2048 -days 365 -nodes -keyout private.key \
            -out cert.csr -subj "/CN=$USERNAME"
log "CSR for user $USERNAME is created and"

ipa cert-request cert.csr --principal="$USERNAME" --certificate-out cert.pem
log "Certificate for user $USERNAME is created in cert.pem"
