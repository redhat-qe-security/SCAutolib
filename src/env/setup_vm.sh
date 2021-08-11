#!/usr/bin/bash
# author: Pavel Yadlouski <pyadlous@redhat.com>
set -e
. "$(dirname "$0")/logs.sh" || exit 1

rx='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'

NAME='default-name'
IMG_NAME='rhel-guest-image-8.4.x86_64.qcow2'
IMG_PATH='/var/lib/libvirt/images'
SCRIPT=""
NFS_DIR=1
KEY=""
RUN=0
RHEL="8.5"
REPO_FILE=""


while (("$#")); do
  case "$1" in
  --rhel)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      RHEL=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
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

  -k | --key)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      KEY=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  -s | --script)
    if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
      SCRIPT=$2
      shift 2
    else
      echo "Error: Argument for $1 is missing" >&2
      exit 1
    fi
    ;;
  --run-script)
    RUN=1
    shift
    ;;
  -N | --no-nfs)
    NFS_DIR=0
    shift
    ;;
  -h | --help)
    help
    shift
    ;;
  -*) # unsupported flags
    echo "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  esac
done

IMG_NAME="$NAME.qcow2"
if [[ -z $REPO_FILE ]]; then
  REPO_FILE="$(dirname "$(realpath "$0")")/redhat-$RHEL.repo"
fi

if [ -d /home/pyadlous/os_dir ]
then
  cp -L /home/pyadlous/os_dir/latest-"$RHEL" /var/lib/libvirt/images/"$IMG_NAME"
  log "Image $(readlink /home/pyadlous/os_dir/latest-"$RHEL") is copied to /var/lib/libvirt/images/$IMG_NAME"
fi

# TODO add key for VM with full path or just a name?
if [[ $KEY == "" ]]; then
  ssh-keygen -f "$HOME"/.ssh/"$NAME".key -q -N ""
  KEY="$HOME/.ssh/${NAME}.key.pub"
  chmod 600 "$HOME/.ssh/${NAME}.key"
  log "ssh key is generated into ${KEY}"
fi

log "Run system preparations for installing RHEL-$RHEL"
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
  --os-variant rhel-unknown \
  --name "$NAME" \
  --check all=off \
  --disk path="$IMG_PATH/$IMG_NAME"

warn "Waiting for VM start"
ip_rhel=""
set +e
while [[ -z "$ip_rhel" ]]; do
    echo -n "."
    sleep 1
    ip_rhel=$(virsh domifaddr "$NAME" | grep -o -E "$rx\.$rx\.$rx\.$rx")
done
echo
set -e
log "VM $NAME is started"
log "IP address of the VM: ${bold}${ip_rhel}${normal}"

echo -e \
"Host $NAME
    Hostname $ip_rhel
  	Preferredauthentications publickey
  	User root
  	UserKnownHostsFile /dev/null
    StrictHostKeyChecking no
    IdentityFile $KEY
    " >> "$(dirname "$KEY")"/config
log "New entry is created in the $(dirname "$KEY")/config for address $ip_rhel with name $NAME"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "dnf update -y"
log "Updating system complete"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "dnf install vim -y "
log "VIM installed"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "dnf install gdm -y "
log "GDM installed"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "dnf install python3 python3-pip -y "
log "Python3 installed"

ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "yum groupinstall 'Smart Card Support' -y"
log "Group Smart Card Support is installed"

if [[ "$NFS_DIR" -eq 1 ]]
then
  for path in $(showmount -e localhost | grep -P -o  "\/[a-zA-Z\/_\-0-9]* ")
  do
    name=$(basename "$path")
    ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "mkdir /root/$name && mount.nfs 192.168.122.1:$path /root/$name"
    log "NFS directory $path is mounted into /root/$name"

    ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "echo \"192.168.122.1:$path /root/$name nfs defaults 0 0\" >> /etc/fstab"
    log "NFS directory $path is added to /etc/fstab for automount to /root/$name"
  done
fi

cmd="pip3 install --upgrade pip && pip3 install --upgrade -I -r /root/SCAutolib/src/env/requirements.txt "
ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "$cmd"
log "Python requirements are installed"

cmd='mkdir -p $(python3 -m site --user-site) && ln -sf /root/SCAutolib $(python3 -m site --user-site)'
ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "$cmd"
log "SCAutolib is added for python imports to user-site derectory"

cmd="hostnamectl set-hostname $NAME --static"
ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" "$cmd"
log "Hostname is set to $NAME"

# if $LOCAL != 0
# then
#     dnf install nfs-utils
#     echo "$LOCAL ${ip_rhel}(rw,no_root_squash)"
#     systemctl enable --now nfs-server
#     firewall-cmd --zone=libvirt --permanent --add-service=nfs
#     firewall-cmd --zone=libvirt --permanent --add-service=mountd
#     firewall-cmd --zone=libvirt --permanent --add-service=rpc-bind
#     firewall-cmd --reload
#     systemctl restart firewalld
#     systemctl start nfs-server
#     echo "[LOG] Local NFS server for folder $LOCAL is configured "
#     ssh -o StrictHostKeyChecking=no -i vm_key root@$ip_rhel bash /root/$SCRIPT -l ${my_local_IP}:${LOCAL} # TODO my_local_ip
# else
#     ssh -o StrictHostKeyChecking=no -i vm_key root@$ip_rhel bash /root/$SCRIPT
# fi

if [[ "$SCRIPT" !=  "" ]]
then
  scp -o StrictHostKeyChecking=no -i "$KEY" "$SCRIPT" root@"$ip_rhel":/root/"$(basename "$SCRIPT")"
  log "Script $SCRIPT is copied to /root/$SCRIPT"
  if [[ $RUN -eq 1 ]]
  then
    ssh -o StrictHostKeyChecking=no -i "$KEY" root@"$ip_rhel" bash "/root/$SCRIPT"
    log "Script ${SCRIPT} for ${ip_rhel} is finished"
  fi
fi

virsh snapshot-create-as --domain "$NAME" --name "initial"

ssh -i "$KEY" root@"$ip_rhel"
