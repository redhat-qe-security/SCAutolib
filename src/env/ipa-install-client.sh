#!/usr/bin/sh

set -e

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

CLIENT_HOSTNAME='ipa-client.sc.test.com'
SERVER_HOSTNAME='ipa-server.sc.test.com'
DOMAIN_NAME='sc.test.com'
REALM="SC.TEST.COM"
ADMIN_PASSWD="SECret.123"
USERNAME="ipa-user"

function log() {
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

yum install @idm:DL1 -y
dnf -y copr enable jjelen/vsmartcard
yum install freeipa-client virt_cacard softhsm -y
log "Necessary packages are installed"

if [[ -z $1 ]]
then
  echo "No IP address is provided"
  exit 1
fi

echo "$1 $SERVER_HOSTNAME" >> /etc/hosts
log "New entry '$1 $SERVER_HOSTNAME' is added to /etc/hosts"

hostnamectl set-hostname "$CLIENT_HOSTNAME" --static
log "Hostname is set to $CLIENT_HOSTNAME"

echo -e "yes\nyes" | ipa-client-install -p admin --password "$ADMIN_PASSWD" --server "$SERVER_HOSTNAME" --domain "$DOMAIN_NAME" --realm "$REALM" --hostname "$CLIENT_HOSTNAME" --all-ip-addresses  --force --force-join  --no-ntp
log "IPA client is installed"

kinit admin
log "Kerberos ticket for admin user is obtained"

ipa user-add "$USERNAME" --last last --first first --cn "$USERNAME"
log "User '$USERNAME' is added to IPA server"

openssl req -new -newkey rsa:2048 -days 365 -nodes -keyout private.key -out cert.csr -subj "/CN=$USERNAME"
log "CSR for user $USERNAME is created and"

ipa cert-request cert.csr --principal=$USERNAME --certificate-out cert.pem
log "Certificate for user $USERNAME is created in cert.pem"