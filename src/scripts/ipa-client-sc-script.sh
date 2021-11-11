#!/bin/sh
# ----------------------------------------------------------------------
# Instructions for enabling Smart Card authentication on  a single IPA
# client. Configures Smart Card daemon, set the system-wide trust store
# and configures SSSD to allow smart card logins to desktop
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
if which yum >/dev/null
then
  PKGMGR=yum
else
  PKGMGR=dnf
fi
rpm -qi pam_pkcs11 > /dev/null
if [ "$?" -eq "0" ]
then
  $PKGMGR remove -y pam_pkcs11 || exit 1
fi
if [ "$?" -ne "0" ]
then
  echo "Could not remove pam_pkcs11 package" >&2
  exit 1
fi
# authconfig often complains about missing dconf, install it explicitly
if which yum >/dev/null
then
  PKGMGR=yum
else
  PKGMGR=dnf
fi
rpm -qi opensc dconf > /dev/null
if [ "$?" -ne "0" ]
then
  $PKGMGR install -y opensc dconf
fi
if [ "$?" -ne "0" ]
then
  echo "Could not install OpenSC package" >&2
  exit 1
fi
if which yum >/dev/null
then
  PKGMGR=yum
else
  PKGMGR=dnf
fi
rpm -qi krb5-pkinit-openssl > /dev/null
if [ "$?" -ne "0" ]
then
  $PKGMGR install -y krb5-pkinit-openssl
fi
if [ "$?" -ne "0" ]
then
  echo "Failed to install Kerberos client PKINIT extensions." >&2
  exit 1
fi
systemctl start pcscd.service pcscd.socket && systemctl enable pcscd.service pcscd.socket
if modutil -dbdir /etc/pki/nssdb -list | grep -q OpenSC
then
  echo "OpenSC PKCS#11 module already configured"
else
  echo "" | modutil -dbdir /etc/pki/nssdb -add "OpenSC" -libfile /usr/lib64/opensc-pkcs11.so
fi
mkdir -p /etc/sssd/pki
for ca_cert in $SC_CA_CERTS
do
  certutil -d /etc/pki/nssdb -A -i $ca_cert -n "Smart Card CA $(uuidgen)" -t CT,C,C
  cat $ca_cert >>  /etc/sssd/pki/sssd_auth_ca_db.pem
done
ipa-certupdate
if [ "$?" -ne "0" ]
then
  echo "Failed to update IPA CA certificate database" >&2
  exit 1
fi
# Use either authselect or authconfig to enable Smart Card
# authentication
if [ -f /usr/bin/authselect ]
then
  AUTHCMD="authselect enable-feature with-smartcard"
else
  AUTHCMD="authconfig --enablesssd --enablesssdauth --enablesmartcard --smartcardmodule=sssd --smartcardaction=1 --updateall"
fi
$AUTHCMD
if [ "$?" -ne "0" ]
then
  echo "Failed to configure Smart Card authentication in SSSD" >&2
  exit 1
fi
# Set pam_cert_auth=True in /etc/sssd/sssd.conf
# This step is required only when authselect is used
python3 --version >/dev/null 2>&1
if [ "$?" -eq 0 ]
then
  PYTHON3CMD=python3
else
  PYTHON3CMD=/usr/libexec/platform-python
fi
if [ -f /usr/bin/authselect ]
then
  ${PYTHON3CMD} -c 'from SSSDConfig import SSSDConfig; c = SSSDConfig(); c.import_config(); c.set("pam", "pam_cert_auth", "True"); c.write()'
fi
systemctl restart sssd.service
