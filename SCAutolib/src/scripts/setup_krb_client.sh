CS_IP_ADDR='10.19.34.109'
KRB_IP_ADDR='10.37.180.210'


dnf install -y krb5-libs krb5-workstation ccid opensc esc pcsc-lite pcsc-lite-libs authconfig gdm nss-pam-ldapd

setsebool -P sssd_connect_all_unreserved_ports on

echo "$KRB_IP_ADDR  krb-server.sctesting.redhat.com" >> /etc/hosts
echo "$CS_IP_ADDR  pki1.example.com" >> /etc/hosts
echo "[LOG] IP addresses are added to /etc/hosts"

echo \
"# Configuration snippets may be placed in this directory as well
includedir /etc/krb5.conf.d/


includedir /var/lib/sss/pubconf/krb5.include.d/
[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log


[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    default_ccache_name = KEYRING:persistent:%{uid}
    default_realm = EXAMPLE.COM
    dns_lookup_kdc = false


[realms]
EXAMPLE.COM = {
    pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
    pkinit_cert_match = <KU>digitalSignature
    kdc = krb-server.sctesting.redhat.com
    admin_server = krb-server.sctesting.redhat.com
    pkinit_kdc_hostname = krb-server.sctesting.redhat.com
}


[domain_realm]
    .sctesting.redhat.com = EXAMPLE.COM
    sctesting.redhat.com= EXAMPLE.COM


[appdefaults]
pam = {
    debug = true
    ticket_lifetime = 1h
    renew_lifetime = 3h
    forwardable = true
    krb4_convert = false
}" > /etc/krb5.conf
echo "[LOG] krb5.conf copied"

#echo \
#"[sssd]
#    services = nss, pam
#    domains = shadowutils,ldap
#    debug_level = 9
#
#[nss]
#    debug_level = 9
#
#[pam]
#    pam_cert_auth = True
#    debug_level = 9
#
#[domain/shadowutils]
#    id_provider = files
#    debug_level = 9
#
#[certmap/ldap/kdcuser]
#    maprule = (uid=kdcuser)
#
#[certmap/shadowutils/localuser]
#    matchrule = <SUBJECT>.*UID=localuser.*" > /etc/sssd/sssd.conf
#echo "[LOG] sssd.conf copied"


authselect select sssd with-smartcard with-mkhomedir
echo "[LOG] authselect runned"

dnf install -y oddjob oddjob-mkhomedir
systemctl enable --now oddjobd.service

#yum group install -y "Server with GUI"
#systemctl set-default graphical.target
#echo "[LOG] Group Server with GUI installed"
#
yum group install -y 'Smart Card Support'
echo "[LOG] Group Smart Card Support installed"

#dnf update -y

#reboot now
