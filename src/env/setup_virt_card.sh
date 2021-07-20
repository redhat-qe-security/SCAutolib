#!/usr/bin/bash

set -x -e

bold=$(tput bold)
normal=$(tput sgr0)

CONF_DIR=""
WORK_DIR=""
ENV_PATH=""
function log() {
  echo -e "${bold}[LOG $(date +"%T")]${normal} $1"
}

while getopts c:w:e: flag
do
    case "$flag" in
        c) CONF_DIR=$OPTARG;;
        w) WORK_DIR=$OPTARG;;
        e) ENV_PATH=$OPTARG;;
        *) echo "Invalid flag is used: $flag";;
    esac
done

dnf -y install virt_cacard

export $(grep -v '^#' $ENV_PATH | xargs)

systemctl daemon-reload
echo 'disable-in: virt_cacard' >> /usr/share/p11-kit/modules/opensc.module
systemctl restart pcscd virt_cacard
sleep 10

chmod 600 /etc/sssd/sssd.conf

systemctl stop pcscd.service pcscd.socket virt_cacard sssd
rm -rf /var/lib/sss/{db,mc}/*
systemctl start pcscd sssd

log "End of setup-virt-card script"

exit 0
