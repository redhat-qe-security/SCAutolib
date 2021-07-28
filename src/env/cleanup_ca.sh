#!/usr/bin/bash

set -e
NAME=local-user

while (("$#")); do
  case "$1" in
  --username)
    if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
      NAME=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
    -* | --*=) # unsupported flags
    echo "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  esac
done

dnf remove virt_cacard vpcd -y

RELEASE=$(cat /etc/redhat-release)
if [[ $RELEASE != *"Red Hat Enterprise Linux release 9"*  ]]
then
  dnf -y module disable idm:DL1
  dnf -y copr remove jjelen/vsmartcard
fi

userdel -r ${NAME}

semodule -r virtcacard

rm -f /etc/systemd/system/virt_cacard.service
rm -f /etc/systemd/system/pcscd.service

systemctl daemon-reload
systemctl restart pcscd

pip3 uninstall -r ./requirements.txt -y


exit 0
