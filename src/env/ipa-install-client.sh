#!/usr/bin/bash

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
DIR="/root/$USERNAME"
IP=""
IPA_ROOT=""

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
  -i | --ip)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      IP=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --root)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      IPA_ROOT=$2
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

if [ -z "$IP" ]
then
  echo "No IP address is provided"
  exit 1
fi


yum install @idm:DL1 -y
dnf -y copr enable jjelen/vsmartcard
dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y
yum install freeipa-client virt_cacard softhsm sshpass -y
log "Necessary packages are installed"

echo "$IP $SERVER_HOSTNAME" >> /etc/hosts
log "New entry '$IP $SERVER_HOSTNAME' is added to /etc/hosts"

sed -i "1s/^/nameserver $IP\n/" /etc/resolv.conf
log "IPA server is added to /etc/resolv.conf as first nameserver"

hostnamectl set-hostname "$CLIENT_HOSTNAME" --static
log "Hostname is set to $CLIENT_HOSTNAME"

echo -e "yes\nyes" | ipa-client-install -p admin --password "$ADMIN_PASSWD" \
                      --server "$SERVER_HOSTNAME" --domain "$DOMAIN_NAME" \
                      --realm "$REALM" --hostname "$CLIENT_HOSTNAME" \
                      --all-ip-addresses  --force --force-join  --no-ntp
log "IPA client is installed"

echo "$ADMIN_PASSWD" | kinit admin
log "Kerberos ticket for admin user is obtained"

/usr/libexec/platform-python -c "from configparser import ConfigParser; \
cnf = ConfigParser(); \
cnf.optionxform = str; \
f = open('/etc/sssd/sssd.conf', 'r'); \
cnf.read_file(f);\
f.close; \
cnf.set('sssd', 'certificate_verification', 'no_ocsp');\
[cnf.set(sec, 'debug_level', '9') for sec in cnf.sections()];\
f = open('/etc/sssd/sssd.conf', 'w'); \
cnf.write(f); \
f.close;"
if [ "$?" -ne "0" ]
then
    echo "Failed to modify SSSD config" >&2
    exit 1
else
    log "SSSD is update for no_ocsp for certificate verification"
fi

sshpass -p "$IPA_ROOT" ssh -q -o StrictHostKeyChecking=no root@"$IP" ipa-advise config-client-for-smart-card-auth > ipa-client-sc.sh
chmod +x ipa-client-sc.sh && ./ipa-client-sc.sh /etc/ipa/ca.crt
log "Setup of IPA client for smart card is finished"
