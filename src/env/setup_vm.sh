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
NFS_DIR=1
KEY=""
RUN=0
REPO_FILE="$(dirname $(realpath "$0"))/redhat.repo"

function help() {
  echo "Script for deploying local VM"
  echo -e "\t-h | --help -- this massage"
  echo -e "\t-n | -name -- name of VM. This name you will see in virt-manager"
  echo -e "\t-s -- bash script that would be uploaded on the VM and the executed"
  echo -e "\t-k | --key -- ssh public key that would be copied to VM"
  echo -e "\t-r -- run given script on target host or now (default script is not executed)"
  echo -e "\t-R | --repo-file -- file with repos for given image (default in $REPO_FILE)"

  exit 0
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
  -n | --name)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      NAME=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  -R | --repo-file)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      REPO_FILE=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;

  -k | --ssh-key)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      KEY=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  -N | --no-nfs)
    NFS_DIR=0
    shift
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

IMG_NAME="$NAME.qcow2"


cp -L /home/pyadlous/os_dir/latest /var/lib/libvirt/images/"$IMG_NAME"

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
  --ssh-inject root:file:"$KEY".pub \
  --upload "$REPO_FILE":/etc/yum.repos.d/redhat.repo\
  -a "$IMG_PATH/$IMG_NAME"

log "Installation RHEL8"
log "Default VM name: ${bold}$NAME${normal}"
virt-install \
  --import \
  --memory 2048 \
  --vcpus 2 \
  --noautoconsole \
  --os-variant rhel8-unknown \
  --name "$NAME" \
  --check all=off \
  --disk path="$IMG_PATH/$IMG_NAME"

log "Waiting for VM start"
for _ in {1..10}
do
  echo -n "."
  sleep 1
done
echo

ip_rhel8=$(virsh domifaddr "$NAME" | grep -o -E "$rx\.$rx\.$rx\.$rx")
log "IP address of the VM: ${bold}${ip_rhel8}${normal}"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "dnf update -y"
log "Updating system complete"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "dnf install vim gdm -y "
log "VIM installed"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "yum groupinstall 'Smart Card Support' -y"
log "Group Smart Card Support is installed"

if [ "$NFS_DIR" -eq 1 ]
then
  NFS_SERVER_PATH=$(showmount -e localhost | grep -P -o  "\/[a-zA-Z\/_\-0-9]* ")
  ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "mkdir /root/sc && mount.nfs 192.168.122.1:$NFS_SERVER_PATH /root/sc"
  log "NFS directory $NFS_SERVER_PATH is mounted into /root/sc"

  ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "echo \"192.168.122.1:$NFS_SERVER_PATH /root/sc nfs defaults 0 0\" >> /etc/fstab"
  log "NFS directory $NFS_SERVER_PATH is added to /etc/fstab for automount"
fi

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" "hostnamectl set-hostname $NAME --static"
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

if [ ! "$SCRIPT" ==  "" ]
then
  scp -o StrictHostKeyChecking=no -i "$KEY" "$SCRIPT" root@"$ip_rhel8":/root/
  log "Script $SCRIPT is copied to /root/$SCRIPT"
  if [ $RUN = 1 ]
  then
    ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel8" bash /root/"$SCRIPT"
    log "Script ${SCRIPT} for ${ip_rhel8} is finished"
  fi
fi

echo \
"Host $NAME
    Hostname $ip_rhel8
  	Preferredauthentications publickey
  	User root
    IdentityFile $KEY" >> "$(dirname $KEY)"/config
log "New entry is created in the $(dirname $KEY)/config for address $ip_rhel8 with name $NAME"

virsh snapshot-create-as --domain "$NAME" --name "initial"

ssh -i "$KEY" root@"$ip_rhel8"
