from os.path import (exists, realpath, isfile, dirname, abspath, join, split)
from os import mkdir
import click
import yaml
import subprocess as subp
from shutil import copy
from re import match
from decouple import config
import utils as utils
from time import sleep
from SCAutolib import env_logger
import paramiko
from pysftp import Connection, CnOpts
from configparser import ConfigParser

# TODO add docs about parameters
DIR_PATH = dirname(abspath(__file__))
SETUP_CA = f"{DIR_PATH}/env/setup_ca.sh"
SETUP_VSC = f"{DIR_PATH}/env/setup_virt_card.sh"
CLEANUP_CA = f"{DIR_PATH}/env/cleanup_ca.sh"
WORK_DIR = None
TMP = None
CONF_DIR = None
KEYS = None
CERTS = None
BACKUP = None
CONFIG_DATA = None  # for caching configuration data
KRB_IP = None


@click.group()
def cli():
    pass


@click.command()
@click.option("--setup", "-s", is_flag=True, default=False, required=False,
              help="Flag for automatic execution of local CA and virtual "
                   "smart card deployment")
@click.option("--conf", "-c", type=click.Path(),
              help="Path to YAML file with configurations.", required=False)
@click.option("--work-dir", "-w", type=click.Path(), required=False,
              default=DIR_PATH,
              help="Absolute path to working directory"
                   "Value WORK_DIR in configuration file can overwrite "
                   "this parameter.")
@click.option("--env-file", "-e", type=click.Path(), required=False, default=None,
              help="Absolute path to .env file with environment varibles to be "
                   "used in the library.")
@click.option("--krb", "-k", is_flag=True, required=False, default=False,
              help="Flag for setup of kerberos cleint.")
def prepair(setup, conf, work_dir, env_file, krb):
    """
    Prepair the whole test envrionment including temporary directories, necessary
    configuration files and services. Also can automaticaly run setup for local
    CA and virtual smart card.

    Args:
        krb: if you want to deploy kerberos server and client
        setup: if you want to automatically run other setup steps
        conf: path to configuration file im YAML format
        work_dir: path to working directory. Can be overwritten
                  by varible WORK_DIR in confugration file
        env_file: path to already existing .env file
    """
    # TODO: add geting of work_dir from configuraion file
    env_file = _load_env(env_file, work_dir)

    _prep_tmp_dirs()
    env_logger.debug("tmp directories are created")

    usernames = _read_config(conf, items=["local_user.name",
                                          "krb.name"])
    _create_sssd_config(*usernames)
    env_logger.debug("SSSD configuration file is updated")

    _create_softhsm2_config()
    env_logger.debug("SoftHSM2 configuration file is created in the "
                     f"{CONF_DIR}/softhsm2.conf")

    _create_virtcacard_configs()
    env_logger.debug("Configuration files for virtual smart card are created.")

    _creat_cnf(usernames)

    _create_krb_config(conf)

    if setup:
        _setup_ca(conf, env_file)
        _setup_virt_card(env_file)

    if krb:
        setup_krb_server(conf)
        setup_krb_client(conf)


@click.command()
@click.option("--env", type=click.Path(), required=False, default=None,
              help="Path to .env file with specified variables")
@click.option("--conf", "-c", type=click.Path(), required=True,
              help="Path to YAML file with configurations")
@click.option("--work-dir", type=click.Path(), required=False,
              default=join(DIR_PATH, "virt_card"),
              help=f"Path to working directory. By default is "
                   f"{join(DIR_PATH, 'virt_card')}")
def setup_ca(conf, env_file, work_dir):
    """
    CLI command for setup the local CA.

    Args:
        conf: Path to YAML file with configurations
        work_dir: Path to working directory. By default working directory is
                  in the source directory of the library
        env_file: Path to .env file with specified variables
    """
    # TODO: generate certs for Kerberos
    env_path = _load_env(env_file, work_dir)
    _setup_ca(conf, env_path)


@click.command()
@click.option("--env", type=click.Path(), required=False, default=None,
              help="Path to .env file with specified variables")
@click.option("--work-dir", type=click.Path(), required=False,
              default=join(DIR_PATH, "virt_card"),
              help="Working directory where all necessary files and directories "
                   "are/will be stored")
def setup_virt_card(env, work_dir):
    """
    Setup virtual smart card. Has to be run after configuration of the local CA.

    Args:
        env: Path to .env file with specified variables
        work_dir: Working directory where all necessary files and directories
                  are/will be stored
    """
    env_path = _load_env(env, work_dir)
    _setup_virt_card(env_path)


@click.command()
@click.option("--conf", "-c", type=click.Path(), required=True,
              help="Path to YAML file with configurations")
def setup_krb_client(conf):
    check_env()
    pkgs = ["krb5-libs", "krb5-workstation", "ccid", "opensc", "esc", "pcsc-lite",
            "pcsc-lite-libs", "authconfig", "gdm", "nss-pam-ldapd", "oddjob",
            "oddjob-mkhomedir"]
    subp.run(["dnf", "install", *pkgs, "-y"], check=True)
    env_logger.debug(f"Packages for Kerberos client are installed")

    subp.run(["yum", "groupinstall", "'Smart Card Support'", "-y"])
    env_logger.debug(f"Smart Card Support group is installed")

    if exists("/etc/krb5.conf"):
        utils._backup("/etc/krb5.conf", "krb5-original.conf")

    with open("/etc/krb5.conf", "w") as f:
        f.write("""# Configuration snippets may be placed in this directory as well
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log


[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    default_ccache_name = KEYRING:persistent:%{uid}
    default_realm = EXAMPLE.COM
    dns_lookup_kdc = false

[realms]
EXAMPLE.COM = {
    pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
    pkinit_cert_match = <KU>digitalSignature
    kdc = krb-server.sctesting.redhat.com
    admin_server = krb-server.sctesting.redhat.com
    pkinit_kdc_hostname = krb-server.sctesting.redhat.com
}

[domain_realm]
    .sctesting.redhat.com = EXAMPLE.COM
    sctesting.redhat.com= EXAMPLE.COM


[appdefaults]
pam = {
    debug = true
    ticket_lifetime = 1h
    renew_lifetime = 3h
    forwardable = true
    krb4_convert = false
}""")
    env_logger.debug("File /etc/krb5.conf is updated.")

    subp.run(["setsebool", "-P", "sssd_connect_all_unreserved_ports", "on"], check=True)
    env_logger.debug("SELinux boolean sssd_connect_all_unreserved_ports is set to ON")

    krb_ip_addr = _read_config(conf, ["krb.ip"])
    with open("/etc/hosts", "a") as f:
        f.write(f"{krb_ip_addr} krb-server.sctesting.redhat.com\n")
        env_logger.debug("IP address of kerberos server is added to /etc/hosts file")
    sleep(3)
    utils.restart_service("sssd")
    sleep(3)
    subp.run(["systemctl", "enable", "--now", "oddjobd.service"], check=True)


@click.command()
@click.option("--conf", "-c", type=click.Path(), required=True)
def setup_krb_server(conf):
    check_env()

    _create_krb_config(conf)

    cert, key = _generate_krb_certs()
    env_logger.debug(f"KDC certificat: {cert}")
    env_logger.debug(f"KDC private key: {key}")
    krb_ip, krb_root_passwd = _read_config(conf, ["krb.ip", "krb.root_passwd"])

    # Need for strcit host key cheking disabled
    cnopts = CnOpts()
    cnopts.hostkeys = None
    with Connection(krb_ip, "root", password=krb_root_passwd, cnopts=cnopts) as sftp:
        env_logger.debug(f"SFTP with server {krb_ip} connection established")
        paths = ({"original": "/var/kerberos/krb5kdc/kdc.pem", "new": cert},
                 {"original": "/var/kerberos/krb5kdc/kdckey.pem", "new": key},
                 {"original": "/var/kerberos/krb5kdc/kdc-ca.pem", "new": f"{WORK_DIR}/rootCA.crt"})
        for item in paths:
            name = split(item["original"])[1]
            name = name.replace(".", "-original.")
            if sftp.exists(item["original"]):
                sftp.get(item["original"], f"{BACKUP}/{name}")
                env_logger.debug(f"File {item['original']} from Kerberos server "
                                 f"({krb_ip}) is backuped to {BACKUP}/{name}")
            sftp.put(item["new"], item["original"])
            env_logger.debug(f"File {item['new']} from localhost is copied to "
                             f"Kerberos server ({krb_ip}) to {item['original']}")

        _create_kdc_config(sftp)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(krb_ip, 22, "root", krb_root_passwd)
    env_logger.debug(f"SSH connectin to {krb_ip} is istablished")
    stdin, stdout, stderr = ssh.exec_command("systemctl restart krb5kdc")
    env_logger.debug(f"Service krb5kdc on {krb_ip} is restarted")
    # TODO: check on errors


@click.command()
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def cleanup_ca(conf):
    """
    Cleanup the host after configuration of the testing environment.

    Args:
        conf: path to configuraion file in YAML format
    """
    env_logger.debug("Start cleanup of local CA")

    username = _read_config(conf, ["local_user.name"])
    # TODO: check after adding kerberos user that everything is also OK
    # TODO: clean kerberos info
    out = subp.run(
        ["bash", CLEANUP_CA, "--username", username])

    assert out.returncode == 0, "Something break in cleanup script :("
    env_logger.debug("Cleanup of local CA is completed")


def _create_kdc_config(sftp):
    check_env()
    realm = _read_config(config, ["krb.realm_name"])
    kdc_conf = "/var/kerberos/krb5kdc/kdc.conf"
    env_logger.debug(f"Realm name: {realm}")

    sftp.get(kdc_conf, f"{BACKUP}/kdc-original.conf")
    env_logger.debug(f"File {kdc_conf} is copied to {BACKUP}/kdc-original.conf")

    cnf = ConfigParser()
    cnf.optionxform = str
    with sftp.open(kdc_conf, "r") as f:
        cnf.read_file(f, source="kdc.conf")

        for sec in ["kdcdefaults", "realms"]:
            if not cnf.has_section(sec):
                env_logger.debug(f"Section {sec} is not present in {kdc_conf}.")
                cnf.add_section(sec)
                env_logger.debug(f"Section {sec} in {kdc_conf} is created.")
        present = True
        if not cnf.has_option("realms", realm):
            env_logger.debug(f"Option {realm} is not present in realms section in {kdc_conf}.")
            cnf.set("realms", realm, "{}")
            env_logger.debug(f"Option {realm} is created in realms section in {kdc_conf}.")
            present = False
        # Parse options for realm in {...}

        d = {"acl_file": "/var/kerberos/krb5kdc/kadm5.acl",
             "dict_file": "/usr/share/dict/words",
             "admin_keytab": "/var/kerberos/krb5kdc/kadm5.keytab",
             "supported_enctypes": "aes256-cts:normal aes128-cts:normal "
                                   "arcfour-hmac:normal camellia256-cts:normal "
                                   "camellia128-cts:normal",
             "pkinit_allow_upn": "on",
             "pkinit_eku_checking": "scLogin",
             "max_renewable_life": "7d"}

        if present:
            env_logger.debug(f"Option {realm} presents in realms section in {kdc_conf}.")
            d = {}
            tmp = cnf.get("realms", realm)\
                .replace("{", "").replace("}", "").split("\n")
            tmp = list(filter(None, tmp))
            for i in tmp:
                key, value = [a.strip() for a in i.split("=")]
                d[key] = value

        d["pkinit_anchors"] = "FILE:/var/kerberos/krb5kdc/kdc-ca.pem"
        d["pkinit_identity"] = "FILE:/var/kerberos/krb5kdc/kdc.pem," \
                               "/var/kerberos/krb5kdc/kdckey.pem"

        options = [f"{key} = {value}\n" for key, value in d.items()]
        val = "{\n"
        for opt in options:
            val += opt
        val += "}\n"
        cnf.set("realms", realm, val)
        env_logger.debug(f"Value for option {realm} is {value}")

    with sftp.open(kdc_conf, "w") as f:
        cnf.write(f)
        env_logger.debug(f"File {kdc_conf} is updated")


def check_env():
    """
    Insure that environment variables are loaded from .env file.
    """
    global BACKUP
    global KEYS
    global CERTS
    global TMP
    global CONF_DIR
    global WORK_DIR

    if WORK_DIR is None:
        WORK_DIR = config("WORK_DIR")
    if BACKUP is None:
        BACKUP = config("BACKUP")
    if KEYS is None:
        KEYS = config("KEYS")
    if CERTS is None:
        CERTS = config("CERTS")
    if TMP is None:
        CERTS = config("TMP")
    if CONF_DIR is None:
        CONF_DIR = config("CONF_DIR")


def _create_krb_config(conf):
    check_env()
    realm, username = _read_config(conf, ["krb.realm_name", "krb.name"])

    with open(f"{CONF_DIR}/extensions.kdc", "w") as f:
        f.write(f"""[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
issuerAltName=issuer:copy
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

[kdc_princ_name]
realm=EXP:0,GeneralString:{realm}
principal_name=EXP:1,SEQUENCE:kdc_principal_seq

[kdc_principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:kdc_principals

[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:{realm}""")
        env_logger.debug(f"Extensions file for KDC is created {CONF_DIR}/extensions.kdc")

    with open(f"{CONF_DIR}/extensions.client", "w") as f:
        f.write(f"""[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
issuerAltName=issuer:copy
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

[princ_name]
realm=EXP:0,GeneralString:{realm}
principal_name=EXP:1,SEQUENCE:principal_seq

[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals

[principals]
princ1=GeneralString:{username}""")
        env_logger.debug(f"Extensions file for KDC client is created "
                         f"{CONF_DIR}/extensions.client")


def _generate_krb_certs():
    check_env()
    # TODO: add temaplate file for generatng the certificate
    key_path = f"{KEYS}/kdckey.pem"
    crt_path = f"{CERTS}/kdc.pem"
    subp.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
    subp.run(["openssl", "req", "-new", "-out", "kdc.req", "-key", key_path], check=True)
    subp.run(["openssl", "x509", "-req", "-in", "kdc.req", "-CAkey",
              f"{WORK_DIR}/rootCA.key", "-CA", f"{WORK_DIR}/rootCA.crt", "-out", crt_path, "-days", "365",
              "-extfile", f"{CONF_DIR}/extensions.kdc", "-extensions", "kdc_cert", "-CAcreateserial"], check=True)
    return crt_path, key_path


def _load_env(env_file, work_dir=join(DIR_PATH, "virt_card")) -> str:
    """
    Create .env near source files of the libarary. In .env file following
    variables expected to be present: WORK_DIR, CONF_DIR, TMP, KEYS, CERTS, BACKUP.
    Deployment process would relay on this variables.

    Args:
        env_file:  path to already existing .env file. If given, then it would
                   be just copied to the library.
        work_dir: working directory

    Returns:
        Path to .env file.
    """
    global WORK_DIR
    global CONF_DIR
    global BACKUP

    if env_file is None:
        env_file = f"{DIR_PATH}/.env"
        with open(env_file, "w") as f:
            f.write(f"WORK_DIR={work_dir}\n")
            f.write(f"TMP={join(work_dir, 'tmp')}\n")
            f.write(f"CONF_DIR={join(work_dir, 'conf')}\n")
            f.write(f"KEYS={join(work_dir, 'tmp', 'keys')}\n")
            f.write(f"CERTS={join(work_dir, 'tmp', 'certs')}\n")
            f.write(f"BACKUP={join(work_dir, 'tmp', 'backup')}\n")
    else:
        # .env file should be near source file
        # because this env file is used other source files
        copy(env_file, DIR_PATH)
        env_file = join(DIR_PATH, ".env")
    env_logger.debug("Environment file is created")
    WORK_DIR = work_dir
    CONF_DIR = config("CONF_DIR", cast=str)
    BACKUP = config("BACKUP", cast=str)
    return env_file


def _prep_tmp_dirs():
    """
    Prepair directory structure for test environment. All paths are taken from
    previously loaded env file.
    """
    for dir_env_var in ("WORK_DIR", "TMP", "KEYS", "CERTS", "BACKUP", "CONF_DIR"):
        dir_path = config(dir_env_var, cast=str)
        if not exists(dir_path):
            mkdir(dir_path)


def _creat_cnf(user_list: [], ca: bool = True):
    """
    Create configuration files for OpenSSL to generate certificates and requests.
    Args:
        user_list: list of users for which the configuration file for
                   certificate signing request should be created
        ca: if configuration file for local CA is need to be generated
    """
    if ca:
        ca_cnf = """[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = .
database         = $dir/index.txt
new_certs_dir    = $dir/newcerts

certificate      = $dir/rootCA.crt
serial           = $dir/serial
private_key      = $dir/rootCA.key
RANDFILE         = $dir/rand

default_days     = 365
default_crl_hours = 1
default_md       = sha256

policy           = policy_any 
email_in_dn      = no

name_opt         = ca_default
cert_opt         = ca_default
copy_extensions  = copy

[ usr_cert ]
authorityKeyIdentifier = keyid, issuer

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ policy_any ]
organizationName       = supplied
organizationalUnitName = supplied
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
O  = Example
OU = Example Test
CN = Example Test CA
        """
        with open(f"{CONF_DIR}/ca.cnf", "w") as f:
            f.write(ca_cnf)
            env_logger.debug(f"Confugation file for local CA is created {CONF_DIR}/ca.cnf")

    for user in user_list:
        user_cnf = f"""[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = Example
OU = Example Test
CN = {user}

[ req_exts ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "{user}"
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature
extendedKeyUsage = clientAuth, emailProtection, msSmartcardLogin
subjectAltName = otherName:msUPN;UTF8:{user}@EXAMPLE.COM, email:{user}@example.com
"""
        with open(f"{CONF_DIR}/req_{user}.cnf", "w") as f:
            f.write(user_cnf)
            env_logger.debug(f"Configuraiton file for CSR for user {user} is created "
                             f"{CONF_DIR}/req_{user}.cnf")


def _create_sssd_config(local_user: str = None, krb_user: str = None):
    """
    Update the content of the sssd.conf file. If file exists, it would be store
    to the backup folder and content in would be edited for testing purposes.
    If file doesn't exist, it would be created and filled with default options.

    Args:
        local_user: username for local user with smart card to add the match rule.
        krb_user: username for kerberos user with smart card to add the match rule.
    """

    holder = "#<{holder}>\n"
    content = []
    if exists("/etc/sssd/sssd.conf"):
        utils._backup("/etc/sssd/sssd.conf", name="sssd-original.conf")
        # TODO: make more strict checking of the content in the file
        with open("/etc/sssd/sssd.conf", "r") as f:
            content = f.readlines()
        for index, line in enumerate(content):
            if match(r"^\[(.*)]\n$", line):
                content[index] = line + holder.format(holder=line.rstrip("\n"))
    else:
        content = ["[sssd]\n",
                   "#<[sssd]>\n",
                   "debug_level = 9\n",
                   "services = nss, pam\n",
                   "domains = shadowutils\n",

                   "\n[nss]\n",
                   "#<[nss]>\n",
                   "debug_level = 9\n",

                   "\n[pam]\n",
                   "#<[pam]>\n",
                   "debug_level = 9\n",
                   "pam_cert_auth = True\n",

                   "\n[domain/shadowutils]\n",
                   "#<[domain/shadowutils]>\n"
                   "debug_level = 9\n",
                   "id_provider = files\n"]
    content = "".join(content)

    if local_user:
        if f"[certmap/shadowutils/{local_user}]\n" not in content:
            content = content + f"\n[certmap/shadowutils/{local_user}]\n" + \
                      f"#<[certmap/shadowutils/{local_user}]>\n" + \
                      f"matchrule = <SUBJECT>.*CN={local_user}.*\n"
    if krb_user:
        if f"[certmap/ldap/{krb_user}]\n" not in content:
            content = content + f"\n[certmap/ldap/{krb_user}]\n" + \
                      f"#<[certmap/ldap/{krb_user}]>\n" + \
                      f"maprule = (uid={krb_user})\n"

    with open("/etc/sssd/sssd.conf", "w") as f:
        f.write(content)
        env_logger.debug("Configuration file for SSSD is updated "
                         "in  /etc/sssd/sssd.conf")


def _create_softhsm2_config():
    """
    Create SoftHSM2 configuraion file in conf_dir. Same directory has to be used
    in setup-ca function, otherwise configuraion file wouldn't be found causing
    the error. conf_dir expected to be in work_dir.
    """
    hsm_conf = config("SOFTHSM2_CONF", default=None)
    if hsm_conf is not None:
        with open(f"{BACKUP}/SoftHSM2-conf-env-var", "w") as f:
            f.write(hsm_conf + "\n")
        env_logger.debug(f"Original value of SOFTHSM2_CONF is stored into "
                         f"{BACKUP}/SoftHSM2-conf-env-var file.")
    with open(f"{CONF_DIR}/softhsm2.conf", "w") as f:
        f.write(f"directories.tokendir = {WORK_DIR}/tokens/\n"
                f"slots.removable = true\n"
                f"objectstore.backend = file\n"
                f"log.level = INFO\n")
        env_logger.debug(f"Configuration file for SoftHSM2 is created "
                         f"in {CONF_DIR}/softhsm2.conf.")


def _create_virtcacard_configs():
    """
    Create systemd service (virt_cacard.service) and semodule (virtcacard.cil)
    for virtual smart card.
    """
    # TODO create virt_cacard.service
    service_path = "/etc/systemd/system/virt_cacard.service"
    module_path = f"{CONF_DIR}/virtcacard.cil"
    if exists(service_path):
        utils._backup(service_path, "virt_cacard-original.service")
    if exists(module_path):
        utils._backup(module_path, "virtcacard-original.cil")

    with open(service_path, "w") as f:
        f.write(f"""[Unit]
Description=virt_cacard Service
Requires=pcscd.service

[Service]
Environment=SOFTHSM2_CONF="{CONF_DIR}/softhsm2.conf"
WorkingDirectory={WORK_DIR}
ExecStart=/usr/bin/virt_cacard >> /var/log/virt_cacard.debug 2>&1
KillMode=process

[Install]
WantedBy=multi-user.target
""")
    env_logger.debug(
        f"Service file {service_path} for virtual smart card is created.")

    with open(module_path, "w") as f:
        f.write("""(allow pcscd_t node_t (tcp_socket (node_bind)));

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t (dir (read search)));""")

    env_logger.debug(f"SELinux module create {module_path}")


def _read_config(conf, items: [str] = None) -> list or str:
    """
    Read data from the configuration file and return require items or full
    content.

    Args:
        conf: path to configuration file
        items: list of items to extracrt from the configuration file.
               If None, full contant would be returned

    Returns:
        list with required items
    """
    global CONFIG_DATA
    if CONFIG_DATA is None:
        with open(conf, "r") as file:
            CONFIG_DATA = yaml.load(file, Loader=yaml.FullLoader)
            assert CONFIG_DATA, "Data are not loaded correctly."

    if items is None:
        return CONFIG_DATA
    return_list = []
    for item in items:
        parts = item.split(".")
        value = CONFIG_DATA
        for part in parts:
            if value is None:
                env_logger.debug(
                    f"Key {part} not present in the configuration file. Skip.")
                break

            value = value.get(part)
            if part == parts[-1]:
                return_list.append(value)

    return return_list if len(items) > 1 else return_list[0]


def _setup_ca(conf, env_file):
    check_env()
    assert exists(realpath(conf)), f"File {conf} is not exist."
    assert isfile(realpath(conf)), f"{conf} is not a file."

    env_logger.debug("Start setup of local CA")

    user = _read_config(conf, items=["local_user"])
    out = subp.run(["bash", SETUP_CA,
                    "--username", user["name"],
                    "--userpasswd", user["passwd"],
                    "--pin", user["pin"],
                    "--env", env_file])
    assert out.returncode == 0, "Something break in setup playbook :("
    env_logger.debug("Setup of local CA is completed")


def _setup_virt_card(env_file):
    """
    Call setup scritp fro virtual smart card

    Args:
        env_file: Path to .env file
    """
    check_env()
    env_logger.debug("Start setup of local CA")
    out = subp.run(["bash", SETUP_VSC, "-c", CONF_DIR, "-e", env_file])

    assert out.returncode == 0, "Something break in setup playbook :("
    env_logger.debug("Setup of local CA is completed")


cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(setup_krb_client)
cli.add_command(cleanup_ca)
cli.add_command(prepair)
cli.add_command(setup_krb_server)

if __name__ == "__main__":
    cli()
