#!/usr/bin/bash

set -e

. "$(dirname $0)/logs.sh" || exit 1

ENV_PATH="$(pwd)/../.env"


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

if [ "$ENV_PATH" != "" ]
then
  export $(grep -v '^#' $ENV_PATH | xargs)
fi

rm -rf "$CA_DIR"

rm -f /etc/systemd/system/virt_cacard_*.service
rm -f /etc/systemd/system/pcscd.service

systemctl daemon-reload
systemctl restart pcscd


exit 0
