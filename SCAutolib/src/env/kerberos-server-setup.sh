#!/bin/bash
# Author: Sneha Veranka
# set -x
# trap read debug

CS_IP_ADDR='10.0.150.172'
DOMAIN_NAME='sc.test.com'
FULL_NAME=$(hostname)

dnf groupinstall -y "Smart Card Support"
dnf install -y sshpass ccid nss-pam-ldapd krb5-workstation krb5-libs krb5-pkinit krb5-server krb5-pkinit-openssl nss-tools python3-ldap redhat-pki-tools
#dnf install -y https://dl.fedoraproject.org/pub/epel/kerberos/kerberosepel-release-latest-8.noarch.rpm

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
     pkinit_anchors = FILE:/var/kerberos/krb5kdc/kdc--rhcs-ca.pem
     pkinit_identity = PKCS12:/var/kerberos/krb5kdc/kdc-rhcs.p12
     pkinit_allow_upn = on
     pkinit_eku_checking = scLogin
     max_renewable_life = 7d
}
EOF

echo "
[libdefaults]
    default_realm = EXAMPLE.COM

[realms]
 EXAMPLE.COM = {
    kdc = ${FULL_NAME}:88
    admin_server = ${FULL_NAME}:749
    default_domain = ${DOMAIN_NAME}
    pkinit_anchors = FILE:/var/kerberos/krb5kdc/kdc-rhcs-ca.pem
 }

[domain_realm]
    .${DOMAIN_NAME} = EXAMPLE.COM
    ${DOMAIN_NAME} = EXAMPLE.COM
" > /etc/krb5.conf.d/rhcs

systemctl start pcscd
systemctl stop firewalld

echo redhat > pwdfile
echo "Password file is created in $(pwd)/pwdfile"

NSS_DB=/var/kerberos/krb5kdc/
certutil -N -d ${NSS_DB} --empty-password
echo "NSS database is initialized in ${NSS_DB}"

echo f0c459c8b7220af1aa16e9cf4b0617ea8fdaad28a21c7c95b935e920fw2c > noise
certutil -d /var/kerberos/krb5kdc -R -a -8 ${FULL_NAME} -s CN=${FULL_NAME} -z noise -o req.pem && sed -n '/-----/,$p' req.pem > file2.txt && sed -e "s/\r//g" file2.txt > newfile
echo "Certificate request is genereted to $(pwd)/req.pem"

mkdir /root/nssdb/
pki -d /root/nssdb/ -c SECret.123 client-init --force
echo "NSS database for client PKI is initialized in /root/nssdb/"
echo "$CS_IP_ADDR pki1.example.com" >> /etc/hosts

yes y | pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 client-cert-import --ca-server RootCA
echo "Root CA certificate is imported from pki1.example.com to NSS db in /root/nssdb/"

sshpass -f pwdfile scp -o "StrictHostKeyChecking no" root@$CS_IP_ADDR:/opt/topology-02-CA/ca_admin_cert.p12 .
pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 client-cert-import --pkcs12 ca_admin_cert.p12 --pkcs12-password SECret.123
echo "P12 file from RHCS ${CS_IP_ADDR} is added to /root/nssdb/"

pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-request-submit --csr-file newfile --profile caKDCwiki > submit_req
req_id=$(sed -n -e 's/^.*Request ID: //p' submit_req)
echo "Request is generated with id: ${req_id}"

yes y | pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-request-approve "$req_id" > cert_req
cert_id=$(sed -n -e 's/^.*Certificate ID: //p' cert_req)
echo "Certificate is generated with cert id: ${cert_id}"

pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-show "$cert_id" --encoded --output /var/kerberos/krb5kdc/kdc-rhcs.cert
echo "PKI CA cert is dumped to /var/kerberos/krb5kdc/kdc-rhcs.cert"

certutil -d /var/kerberos/krb5kdc -A -n "KDC Certificate for EXAMPLE.COM" -t "u,u,u" < /var/kerberos/krb5kdc/kdc-rhcs.cert
echo "KDC cert is added to /var/kerberos/krb5kdc"

pki -h pki1.example.com -d /root/nssdb/ -c SECret.123 -P https -p 20443 -n "PKI CA Administrator for Example.Org" ca-cert-show 0x01 --encoded --output /var/kerberos/krb5kdc/kdc-rhcs-ca.pem
echo "Kerberos CA cert is dumped to /var/kerberos/krb5kdc/kdc-rhcs-ca.pem"

certutil -A -d /var/kerberos/krb5kdc -n "Kerberos CA Certificate" -t CT,C,C < /var/kerberos/krb5kdc/kdc-rhcs-ca.pem
echo "Kerberos CA cert is added to /var/kerberos/krb5kdc"

echo redhat >> dbpwd.txt

pushd /var/kerberos/krb5kdc/ || exit 1

pk12util -o kdc-rhcs.p12 -d . -k dbpwd -W '' -n "KDC Certificate for EXAMPLE.COM"
kdb5_util create -s -r EXAMPLE.COM -P redhat

kadmin.local -q "addprinc +requires_preauth kdcuser@EXAMPLE.COM"

systemctl restart krb5kdc.service
systemctl restart kadmin.service
