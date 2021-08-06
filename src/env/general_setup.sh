#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -e
. "$(dirname $0)/logs.sh" || exit 1

while (("$#")); do
  case "$1" in
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

dnf install virt_cacard vpcd -y
log "virt_cacard and vpcd are installed"

packages="vpcd softhsm sssd-tools httpd virt_cacard sssd"
for p in $packages; do
  if [[ $(rpm -q --quiet "$p") == 0 ]]; then
    log "Package $p presents in the system"
  else
    err "Package $p is not installed on the system, but is is required for testing environment"
  fi
done

yum groupinstall "Smart Card Support" -y
log "Smart Card Support group is installed"

exit 0
