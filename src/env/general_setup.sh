#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -e

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'

CA_DIR=""
ENV_PATH=""

function help() {
  echo -e "Script for settingup the local Certificate Authority and virtual smart card"
  echo -e "\t${bold}-h | --help${normal} this message"
  echo -e "\t${bold}-d | --dir${normal} working durectory. At this directory all necessart file structure woudld be created"
  echo -e "\t${bold}--username${normal} user name for the local user"
  echo -e "\t${bold}--userpasswd${normal} password to be set for the local user"
  echo -e "\t${bold}--pin${normal} PIN to be set for the smart card for a given user in --username"
  echo -e "\t${bold}--conf-dir${normal} directory with all necessary configuraion files"
}

function log() {
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

function err() {
  echo -e "${RED}${bold}[ERROR $(date +"%T")]${normal}${NC} $1"
  exit 1
}

while (("$#")); do
  case "$1" in
  -d | --dir)
    CA_DIR=$2
    shift 2
    ;;
  --env)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      ENV_PATH=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  -h | --help)
    help
    shift
    ;;
  -* | --*=) # unsupported flags
    echo "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  esac
done

RELEASE=$(cat /etc/redhat-release)
if [[ $RELEASE != *"Red Hat Enterprise Linux release 9"* ]]; then
  dnf -y module enable idm:DL1
  log "idm:DL1 module is enabled"
  dnf -y copr enable jjelen/vsmartcard
  log "Copr repo for virt_cacard is enabled"
fi

if [ "$ENV_PATH" != "" ]; then
  log "Env file $ENV_PATH is used"
  export "$(grep -v '^#' "$ENV_PATH" | xargs)"
fi

CONF_DIR="/etc/SCAutolib/conf"

dnf -y install vpcd softhsm python3-pip sssd-tools httpd virt_cacard sssd
yum groupinstall "Smart Card Support" -y
log "Necessary packages are installed"

if [[ "$(semodule -l | grep virtcacard)" -ne 0 ]]
then
  log "SELinux module for virt_card is not installed"
  if [ -f "$CONF_DIR/virtcacard.cil" ]
  then
    warning "No $CONF_DIR/virtcacard.cil file, creating..."
    echo -e \
    "(allow pcscd_t node_t (tcp_socket (node_bind)));

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t (dir (read search)));" > "$CONF_DIR/virtcacard.cil"
  fi
  semodule -i "$CONF_DIR/virtcacard.cil"
  log "SELinux module for virt_card is installed"
fi

exit 0
