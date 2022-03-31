#!/bin/sh
# ----------------------------------------------------------------------
# Instructions for enabling Smart Card authentication on  a single IPA
# server. Includes Apache configuration, enabling PKINIT on KDC and
# configuring WebUI to accept Smart Card auth requests. To enable the
# feature in the whole topology you have to run the script on each
# master
# ----------------------------------------------------------------------
if [ "$(id -u)" -ne "0" ]
then
  echo "This script has to be run as root user" >&2
  exit 1
fi
SC_CA_CERTS=$@
if [ -z "$SC_CA_CERTS" ]
then
  echo "You need to provide one or more paths to the PEM files containing CAs signing the Smart Cards" >&2
  exit 1
fi
for ca_cert in $SC_CA_CERTS
do
  if [ ! -f "$ca_cert" ]
  then
    echo "Invalid CA certificate filename: $ca_cert" >&2
    echo "Please check that the path exists and is a valid file" >&2
    exit 1
  fi
done
# Check whether the credential cache is not empty
klist
if [ "$?" -ne "0" ]
then
  echo "Credential cache is empty" >&2
  echo "Use kinit as privileged user to obtain Kerberos credentials" >&2
  exit 1
fi
# Check whether the host is IPA master
ipa server-find $(hostname -f)
if [ "$?" -ne "0" ]
then
  echo "This script can be run on IPA master only" >&2
  exit 1
fi
# make sure bind-utils are installed so that we can dig for ipa-ca
# records
if which yum >/dev/null
then
  PKGMGR=yum
else
  PKGMGR=dnf
fi
rpm -qi bind-utils > /dev/null
if [ "$?" -ne "0" ]
then
  $PKGMGR install -y bind-utils
fi
if [ "$?" -ne "0" ]
then
  echo "Failed to install bind-utils" >&2
  exit 1
fi
# make sure ipa-ca records are resolvable, otherwise error out and
# instruct
# the user to update the DNS infrastructure
ipaca_records=$(dig +short ipa-ca.sc.test.com)
if [ -z "$ipaca_records" ]
then
  echo "Can not resolve ipa-ca records for ${domain_name}" >&2
  echo "Please make sure to update your DNS infrastructure with " >&2
  echo "ipa-ca record pointing to IP addresses of IPA CA masters" >&2
  exit 1
fi
# look for the OCSP directive in ssl.conf
#  if it is present, switch it on
# if it is absent, append it to the end of VirtualHost section
if grep -q 'SSLOCSPEnable ' /etc/httpd/conf.d/ssl.conf
then
  sed -i.ipabkp -r 's/^#*[[:space:]]*SSLOCSPEnable[[:space:]]+(on|off)$/SSLOCSPEnable on/' /etc/httpd/conf.d/ssl.conf
else
  sed -i.ipabkp '/<\/VirtualHost>/i SSLOCSPEnable on' /etc/httpd/conf.d/ssl.conf
fi
# finally restart apache
systemctl restart httpd.service
# store the OCSP upgrade state
/usr/libexec/platform-python -c 'from ipaserver.install import sysupgrade; sysupgrade.set_upgrade_state("httpd", "ocsp_enabled", True)'
# check whether PKINIT is configured on the master
if ipa-pkinit-manage status | grep -q 'enabled'
then
  echo "PKINIT already enabled"
else
  ipa-pkinit-manage enable
  if [ "$?" -ne "0" ]
  then
    echo "Failed to issue PKINIT certificates to local KDC" >&2
    exit 1
  fi
fi
# Enable OK-AS-DELEGATE flag on the HTTP principal
# This enables smart card login to WebUI
output=$(ipa service-mod HTTP/$(hostname -f) --ok-to-auth-as-delegate=True 2>&1)
if [ "$?" -ne "0" -a -z "$(echo $output | grep 'no modifications')" ]
then
  echo "Failed to set OK_AS_AUTH_AS_DELEGATE flag on HTTP principal" >&2
  exit 1
fi
# Allow Apache to access SSSD IFP
/usr/libexec/platform-python -c "import SSSDConfig; from ipaclient.install.client import sssd_enable_ifp; from ipaplatform.paths import paths; c = SSSDConfig.SSSDConfig(); c.import_config(); sssd_enable_ifp(c, allow_httpd=True); c.write(paths.SSSD_CONF)"
if [ "$?" -ne "0" ]
then
  echo "Failed to modify SSSD config" >&2
  exit 1
fi
# Restart sssd
systemctl restart sssd
mkdir -p /etc/sssd/pki
for ca_cert in $SC_CA_CERTS
do
  certutil -d /etc/pki/nssdb -A -i $ca_cert -n "Smart Card CA $(uuidgen)" -t CT,C,C
  cat $ca_cert >>  /etc/sssd/pki/sssd_auth_ca_db.pem
done
for ca_cert in $SC_CA_CERTS
do
  ipa-cacert-manage install $ca_cert -t CT,C,C
  if [ "$?" -ne "0" ]
  then
    echo "Failed to install external CA certificate to IPA" >&2
    exit 1
  fi
done
ipa-certupdate
if [ "$?" -ne "0" ]
then
  echo "Failed to update IPA CA certificate database" >&2
  exit 1
fi
systemctl restart krb5kdc.service
if [ "$?" -ne "0" ]
then
  echo "Failed to restart KDC. Please restart the service manually." >&2
  exit 1
fi
