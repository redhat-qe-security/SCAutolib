#!/usr/bin/sh
set -e

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

rx='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'

SERVER_HOSTNAME='ipa-server.sc.test.com'
DOMAIN_NAME='sc.test.com'
REALM="SC.TEST.COM"
ADMIN_PASSWD="SECret.123"

function log() {
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

dnf install @idm:DL1 -y
dnf install firewalld freeipa-server ipa-server-dns -y
log "Necessary packages are installed"

systemctl enable firewalld --now
log "Firewall is enabled"

firewall-cmd --add-service={http,https,dns,ntp,freeipa-ldap,freeipa-ldaps} --permanent
firewall-cmd --reload
log "Firewall is configured for IPA server"

hostnamectl set-hostname "$SERVER_HOSTNAME" --static
hostname "$SERVER_HOSTNAME"
log "Hostname is set to $SERVER_HOSTNAME"

entry="$(hostname -I | grep -o -E "$rx\.$rx\.$rx\.$rx") $SERVER_HOSTNAME"
echo "$entry" >> /etc/hosts
log "Entry $entry is added to /etc/hosts file"

ipa-server-install -U -p "$ADMIN_PASSWD" -a "$ADMIN_PASSWD" --realm "$REALM" --hostname "$SERVER_HOSTNAME" --domain "$DOMAIN_NAME" --no-ntp
log "IPA server is installed"

kinit admin
log "Kerberos ticket for admin is obtained"

ipa-advise config-server-for-smart-card-auth > ipa-server-sc.sh
log "Script for config-server-for-smart-card-auth is generated to ipa-server-sc.sh"

chmod +x ipa-server-sc.sh && ./ipa-server-sc.sh /etc/ipa/ca.crt
log "Script ipa-server-sc.sh is finished"

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

systemctl restart sssd
log "SSSD is restarted"
