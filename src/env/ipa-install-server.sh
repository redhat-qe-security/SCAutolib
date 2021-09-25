#!/usr/bin/bash
set -e

rx='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'

SERVER_HOSTNAME='ipa-server-beaker.sc.test.com'
DOMAIN_NAME='sc.test.com'
REALM="SC.TEST.COM"
ADMIN_PASSWD="SECret.123"

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
YELLOW='\033[0;33m'

log() {
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

err() {
  echo -e "${RED}${bold}[ERROR $(date +"%T")]${normal}${NC} $1"
  exit 1
}

warn() {
  echo -e "${YELLOW}${bold}[WARNING $(date +"%T")]${normal}${NC} $1"
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

ip=$(hostname -I | grep -o -E "$rx\.$rx\.$rx\.$rx")
entry="$ip $SERVER_HOSTNAME"
echo "$entry" >> /etc/hosts
log "Entry $entry is added to /etc/hosts file"

ipa-server-install -U -p "$ADMIN_PASSWD" -a "$ADMIN_PASSWD" --realm "$REALM" --hostname "$SERVER_HOSTNAME" --domain "$DOMAIN_NAME" --no-ntp
log "IPA server is installed"

ipa-dns-install --allow-zone-overlap --auto-forwarders --ip-address "$ip"  --no-dnssec-validation --no-reverse
log "DNS for IPA server is configured"

echo "$ADMIN_PASSWD" | kinit admin
log "Kerberos ticket for admin is obtained"

ipa certmaprule-add ipa_default_rule \
    --maprule='(|(userCertificate;binary={cert!bin})(ipacertmapdata=X509: <I>{issuer_dn!nss_x500}<S>{subject_dn!nss_x500}))' \
    --matchrule="<ISSUER>CN=Certificate Authority,O=$REALM" \
    --domain="$DOMAIN_NAME"
log "Default certmap rule is added"

ipa sudocmd-add --desc "List given directory" /usr/bin/ls
log "Sudo command is added"

ipa sudorule-add "General" --desc "General sudo rule" --usercat all --hostcat all --cmdcat all
log "General sudo rule is added"

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
[cnf.set(sec, 'debug_level', '9') for sec in cnf.sections()];\
f = open('/etc/sssd/sssd.conf', 'w'); \
cnf.write(f); \
f.close;"
if [ "$?" -ne "0" ]
then
    echo "Failed to modify SSSD config" >&2
    exit 1
else
    log "SSSD is update. debug_level = 9 for all sections"
fi

systemctl restart sssd
log "SSSD is restarted"
