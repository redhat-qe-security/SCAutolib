#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -e
. "$(dirname "$0")/logs.sh" || exit 1
INSTALL_MISSING=0
packages="softhsm sssd-tools httpd sssd sshpass"

install_pkgs(){
  install="$1"
  if [[ -z "$install" ]]; then
    while true; do
      warn "Do you want to install missing pakages? [y/n]"
      read -r install
      if [[ $install != "y" && $install != "n" ]]; then
        warn "Unknown option, try again..."
        continue
      else
        break
      fi
    done
  fi

  if [[ $install == "y" ]]; then
    for p in $packages; do
      dnf install "$p" -y
      log "Package $p is installed"
    done
  fi
}

while (("$#")); do
  case "$1" in
  --install-missing)
    INSTALL_MISSING=1
    shift
    ;;
  -h | --help)
    shift
    ;;
  -*) # unsupported flags
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

if [[ $INSTALL_MISSING -eq 1 ]]; then
  install_pkgs "y"
else
  install_pkgs ""
fi

for p in $packages; do
  package_version=$(rpm -qa "$p")
  if [[ -z  "$package_version" ]] ; then
    err "Package $p is not installed on the system, but is is required for testing environment"
  fi
  log "Package $package_version presents in the system"
done

yum groupinstall "Smart Card Support" -y
log "Smart Card Support group is installed"

exit 0
