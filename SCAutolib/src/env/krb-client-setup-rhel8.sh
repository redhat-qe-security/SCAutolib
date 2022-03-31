CS_IP_ADDR='10.0.150.172'
KRB_IP_ADDR='192.168.122.69'
DOMAIN='example.com'
DEFAULT_REALM="EXAMPLE.COM"
KRB_HOSTNAME='krb-server.example.com'

#adduser user -m
#useradd localuser -m
#usermod -aG wheel user
#
#echo "user1234" | passwd user --stdin
#echo "[LOG] Usernames user and localuser added"
#
#echo "[LOG] redhat.repo copied"

dnf update -y 

dnf install -y krb5-libs krb5-workstation ccid opensc esc pcsc-lite pcsc-lite-libs authconfig gdm nss-pam-ldapd

setsebool -P sssd_connect_all_unreserved_ports on

echo "$KRB_IP_ADDR $KRB_HOSTNAME" >> /etc/hosts
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
    default_realm = $DEFAULT_REALM
    dns_lookup_kdc = false


[realms]
EXAMPLE.COM = {
    pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
    pkinit_cert_match = <KU>digitalSignature
    kdc = $KRB_HOSTNAME
    admin_server = $KRB_HOSTNAME
    pkinit_kdc_hostname = $KRB_HOSTNAME
}


[domain_realm]
    .$DOMAIN = $DEFAULT_REALM
    $DOMAIN = $DEFAULT_REALM


[appdefaults]
pam = {
    debug = true
    ticket_lifetime = 1h
    renew_lifetime = 3h
    forwardable = true
    krb4_convert = false
}" > /etc/krb5.conf
echo "[LOG] krb5.conf copied"

echo \
"[sssd]
    services = nss, pam
    domains = shadowutils,ldap
    debug_level = 9

[nss]
    debug_level = 9

[pam]
    pam_cert_auth = True
    debug_level = 9

[domain/shadowutils]
    id_provider = files
    debug_level = 9

[certmap/ldap/kdcuser3]
    maprule = (uid=kdcuser3)

[certmap/shadowutils/localuser]
    matchrule = <SUBJECT>.*UID=localuser.*" > /etc/sssd/sssd.conf 
echo "[LOG] sssd.conf copied"

#while getopts l: flag
#do
#    case "${flag}" in
#        l)
#            dnf install nfs-utils
#            mkdir /root/tmp
#            echo "${OPTARG} /root/tmp nfs rw,hard,intr" >> /etc/fstab
#            echo "[LOG] Shared folder ${OPTARG} added to /etc/fstab"
#            mount.nfs ${OPTARG} /root/tmp
#            echo "[LOG] Shared folder ${OPTARG} is set to /root/tmp"
#            ;;
#    esac
#done

authselect select sssd with-smartcard with-mkhomedir
echo "[LOG] authselect runned"

dnf install -y oddjob oddjob-mkhomedir
systemctl enable --now oddjobd.service

#dnf groupinstall -y "Server with GUI"
#systemctl set-default graphical.target
#echo "[LOG] Group Server with GUI installed"
#
#dnf groupinstall -y 'Smart Card Support'
#echo "[LOG] Group Smart Card Support installed"

reboot now
