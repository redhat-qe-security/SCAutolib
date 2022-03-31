#!/bin/bash
# Author: Sneha Veranka
# set -x
# trap read debug

CS_IP_ADDR='10.19.34.100'
DOMAIN_NAME='sctesting.redhat.com'
FULL_NAME="krb-server.$DOMAIN_NAME"

mv /etc/yum.repos.d/beaker* ~

dnf groupinstall -y "Smart Card Support"
dnf install -y ccid opensc esc pcsc-lite pcsc-lite-libs gdm nss-pam-ldapd krb5-workstation krb5-libs krb5-pkinit krb5-server krb5-pkinit-openssl nss-tools python3-ldap

cat > /var/kerberos/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
EXAMPLE.COM = {
     #master_key_type = aes256-cts
     acl_file = /var/kerberos/krb5kdc/kadm5.acl
     dict_file = /usr/share/dict/words
     admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
     supported_enctypes = aes256-cts:normal aes128-cts:normal arcfour-hmac:normal camellia256-cts:normal camellia128-cts:normal
     pkinit_anchors = FILE:/var/kerberos/krb5kdc/kdc-ca.pem
     pkinit_identity = FILE:/var/lib/krb5kdc/kdc.pem,/var/lib/krb5kdc/kdckey.pem
     pkinit_allow_upn = on
     pkinit_eku_checking = scLogin
     max_renewable_life = 7d
}
EOF

cat > /etc/krb5.conf <<EOF
# Configuration snippets may be placed in this directory as well
includedir /etc/krb5.conf.d/

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
    default_realm = EXAMPLE.COM
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
 EXAMPLE.COM = {
    kdc = $(hostname):88
    admin_server = $(hostname)
    default_domain = ${DOMAIN_NAME}
    pkinit_anchors = FILE:/var/kerberos/krb5kdc/kdc-ca.pem
 }

[domain_realm]
    .${DOMAIN_NAME} = EXAMPLE.COM
    ${DOMAIN_NAME} = EXAMPLE.COM
EOF

systemctl start pcscd
systemctl stop firewalld

echo redhat > pwdfile
certutil -N -d /var/kerberos/krb5kdc/ --empty-password
echo f0c459c8b7220af1aa16e9cf4b0617ea8fdaad28a21c7c95b935e920fw2c > noise
certutil -d /var/kerberos/krb5kdc -R -a -8 $(hostname) -s CN=$(hostname) -z noise > req.pem && sed -n '/-----/,$p' req.pem > file2.txt && sed -e "s/\r//g" file2.txt > newfile
dnf module enable -y pki-core
dnf install -y pki-tools

pki -d /root/nssdb/ -c SECret.123 client-init --force
echo $CS_IP_ADDR pki1.example.com >> /etc/hosts

yes y | pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 client-cert-import --ca-server RootCA
dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

dnf install -y sshpass
sshpass -f pwdfile scp -o "StrictHostKeyChecking no" root@$CS_IP_ADDR:/opt/topology-02-CA/ca_admin_cert.p12 .
pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 client-cert-import --pkcs12 ca_admin_cert.p12 --pkcs12-password SECret.123
pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-request-submit --csr-file newfile --profile caKDCwiki > submit_req
req_id=$(sed -n -e 's/^.*Request ID: //p' submit_req)
yes y | pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-request-approve $req_id > cert_req
cert_id=$(sed -n -e 's/^.*Certificate ID: //p' cert_req)
pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-show $cert_id --encoded --output /var/kerberos/krb5kdc/kdc.cert
certutil -d /var/kerberos/krb5kdc -A -n "KDC Certificate for EXAMPLE.COM" -t "u,u,u" < /var/kerberos/krb5kdc/kdc.cert
pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-show 0x01 --encoded --output /var/kerberos/krb5kdc/kdc-ca.pem
certutil -A -d /var/kerberos/krb5kdc -n "Kerberos CA Certificate" -t CT,C,C < /var/kerberos/krb5kdc/kdc-ca.pem

cd /var/kerberos/krb5kdc/
pk12util -o kdc.p12 -d . -k dbpwd -W '' -n "KDC Certificate for EXAMPLE.COM"

kdb5_util create -s -r EXAMPLE.COM -P redhat
kadmin.local -q "addprinc +requires_preauth kdcuser"
systemctl restart krb5kdc.service
systemctl restart kadmin.service
# kinit kdcuser
