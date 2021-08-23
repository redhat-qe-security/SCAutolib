#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -e
. "$(dirname "$0")/logs.sh" || exit 1
INSTALL_MISSING=""
packages="softhsm sssd-tools httpd sssd sshpass"

install_pkgs(){
  RELEASE=$(cat /etc/redhat-release)
  if [[ $RELEASE != *"Red Hat Enterprise Linux release 9"* ]]; then
    dnf install @idm:DL1 -y
    dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y
  fi

  pkg="$1"
  if [[ -z "$INSTALL_MISSING" ]]; then
    while true; do
      warn "Do you want to install missing pakages? [y/n]"
      read -r INSTALL_MISSING
      if [[ $INSTALL_MISSING != "y" && $INSTALL_MISSING != "n" ]]; then
        warn "Unknown option, try again..."
        continue
      else
        break
      fi
    done
  fi

  if [[ $INSTALL_MISSING == "y" ]]; then
      dnf install "$pkg" -y
      log "Package $pkg is installed"
  fi
}

while (("$#")); do
  case "$1" in
  --install-missing)
    INSTALL_MISSING="y"
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

for p in $packages; do
  package_version=$(rpm -qa "$p")
  if [[ -z  "$package_version" ]] ; then
    warn "Package $p is not installed on the system, but is is required for testing environment"
    install_pkgs "$p"
  fi
  log "Package $package_version presents in the system"
done

yum groupinstall "Smart Card Support" -y
log "Smart Card Support group is installed"

exit 0
