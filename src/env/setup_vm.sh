#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
#!/usr/bin/bash
set -e
#trap read debug

bold=$(tput bold)
normal=$(tput sgr0)
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
rx='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'

NAME='default-name'
IMG_NAME='rhel-guest-image-8.4.x86_64.qcow2'
IMG_PATH='/var/lib/libvirt/images'
SCRIPT=""
LOCAL=0
KEY=""
RUN=0
FILE_PATH=$(dirname $(realpath "$0"))

function help() {
  echo "Script for deploying local VM"
  echo -e "\t-h -- this massage"
  echo -e "\t-i -- QCOW2 image name. Should be a name of image that you want to use in /var/lib/libvirt/images/ directory"
  echo -e "\t-n -- name of VM. This name you will see in virt-manager"
  echo -e "\t-s -- bash script that would be uploaded on the VM and the executed"
  echo -e "\t-k -- ssh public key that would be copied to VM"
  echo -e "\t-r -- run given script on target host or now (default script is not executed)"
  exit 0
}

function log() {
  echo -e "${GREEN}${bold}[LOG $(date +"%T")]${normal}${NC} $1"
}

function err() {
  echo -e "${RED}${bold}[ERROR $(date +"%T")]${normal}${NC} $1"
  exit 1
}

while getopts i:n:s:l:k:hr flag; do
  case "${flag}" in
  i) IMG_NAME=${OPTARG} ;;
  n) NAME=${OPTARG} ;;
  s) SCRIPT=${OPTARG} ;;
  k) KEY=${OPTARG} ;;
  r) RUN=1 ;;
  h) help ;;
  *) echo "Invalid flag" ;;
  esac
done

# TODO add key for VM with full path or just a name?
if [[ $KEY == "" ]]; then
  ssh-keygen -f "$HOME"/.ssh/"$NAME".key -q -N ""
  KEY="$HOME/.ssh/${NAME}.key.pub"
  chmod 600 "$HOME/.ssh/${NAME}.key"
  log "ssh key is generated into ${KEY}"
fi

log "Run system preparations for installing RHEL8"
log "Default root password: ${bold}redhat${normal}"
log "Image path $IMG_PATH/$IMG_NAME"
virt-sysprep \
  --uninstall cloud-init \
  --selinux-relabel \
  --root-password password:redhat \
  --ssh-inject root:file:${KEY}.pub \
  -a $IMG_PATH/$IMG_NAME

log "Installation RHEL8"
log "Default VM name: ${bold}$NAME${normal}"
virt-install \
  --import \
  --memory 2048 \
  --vcpus 2 \
  --noautoconsole \
  --os-variant rhel8.4 \
  --name $NAME \
  --check all=off \
  --disk path=$IMG_PATH/$IMG_NAME

log "Whating for VM start"
for _ in {1..10}
do
  echo -n "."
  sleep 1
done
echo

ip_rhel8=$(virsh domifaddr "$NAME" | grep -o -E "$rx\.$rx\.$rx\.$rx")
log "IP address of the VM: ${bold}${ip_rhel8}${normal}"

scp -o StrictHostKeyChecking=no -i "$KEY" "$FILE_PATH/redhat.repo" root@"$ip_rhel8":/etc/yum.repos.d/redhat.repo
log "Repo file for RHEL 8.5 is copied"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "dnf update -y"
log "Updating system complete"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "dnf install vim -y "
log "VIM installed"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "mkdir /root/sc && mount.nfs 192.168.122.1:/home/pyadlous/work/crypto/sc/Sanity/basics /root/sc"
log "NFS is mounted into /root/sc"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "hostnamectl set-hostname $NAME"
log "Hostname is set to $NAME"

# if $LOCAL != 0
# then
#     dnf install nfs-utils
#     echo "$LOCAL ${ip_rhel8}(rw,no_root_squash)"
#     systemctl enable --now nfs-server
#     firewall-cmd --zone=libvirt --permanent --add-service=nfs
#     firewall-cmd --zone=libvirt --permanent --add-service=mountd
#     firewall-cmd --zone=libvirt --permanent --add-service=rpc-bind
#     firewall-cmd --reload
#     systemctl restart firewalld
#     systemctl start nfs-server
#     echo "[LOG] Local NFS server for folder $LOCAL is configured "
#     ssh -o StrictHostKeyChecking=no -i vm_key root@$ip_rhel8 bash /root/$SCRIPT -l ${my_local_IP}:${LOCAL} # TODO my_local_ip
# else
#     ssh -o StrictHostKeyChecking=no -i vm_key root@$ip_rhel8 bash /root/$SCRIPT
# fi

if [[ ! "$SCRIPT" = "" ]]; then
  scp -o StrictHostKeyChecking=no -i "$KEY" "$SCRIPT" root@"$ip_rhel8":/root/
  log "Script $SCRIPT is copied to /root/$SCRIPT"
  if [ $RUN = 1 ]; then
    ssh -o StrictHostKeyChecking=no -i "$KEY" root@$ip_rhel8 bash /root/$SCRIPT
    log "Script ${SCRIPT} for ${ip_rhel8} is finished"
  fi
fi

ssh -i "$KEY" root@"$ip_rhel8"
