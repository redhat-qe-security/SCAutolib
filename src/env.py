from posixpath import join
from subprocess import run, PIPE, Popen, CalledProcessError, check_output
from configparser import ConfigParser
from os.path import (exists, split)
from os import chmod
from pathlib import Path
import python_freeipa as pipa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pwd
from decouple import config
from SCAutolib import env_logger
from SCAutolib.src import utils, exceptions
from SCAutolib.src import *


def create_cnf(user, conf_dir=None, ca_dir=None):
    """
    Create configuration files for OpenSSL to generate certificates and requests.
    """
    if user == "ca":
        if ca_dir is None:
            env_logger.warn("Parameter ca_dir is None. Try to read from config file")
            ca_dir = read_config("ca_dir")
            if ca_dir is None:
                env_logger.error("No value for ca_dir in config file")
                raise exceptions.NoDirProvided("ca_dir")

        if conf_dir is None:
            conf_dir = join(ca_dir, "conf")
        ca_cnf = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = {ca_dir}
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
CN = Example Test CA"""

        with open(f"{conf_dir}/ca.cnf", "w") as f:
            f.write(ca_cnf)
            env_logger.debug(
                f"Configuration file for local CA is created {conf_dir}/ca.cnf")
        return

    user_cnf = f"""
[ req ]
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
    if conf_dir is None:
        raise exceptions.NoDirProvided("conf_dir")
    with open(f"{conf_dir}/req_{user}.cnf", "w") as f:
        f.write(user_cnf)
        env_logger.debug(f"Configuration file for CSR for user {user} is created "
                         f"{conf_dir}/req_{user}.cnf")


def create_sssd_config():
    """
    Update the content of the sssd.conf file. If file exists, it would be store
    to the backup folder and content in would be edited for testing purposes.
    If file doesn't exist, it would be created and filled with default options.
    """
    cnf = ConfigParser(allow_no_value=True)
    cnf.optionxform = str  # Needed for correct parsing of uppercase words
    default = {
        "sssd": {"#<[sssd]>": None,
                 "debug_level": "9",
                 "services": "nss, pam",
                 "domains": "shadowutils"},
        "nss": {"#<[nss]>": None,
                "debug_level": "9"},
        "pam": {"#<[pam]>": None,
                "debug_level": "9",
                "pam_cert_auth": "True"},
        "domain/shadowutils": {"#<[domain/shadowutils]>": None,
                               "debug_level": "9",
                               "id_provider": "files"},
    }

    cnf.read_dict(default)

    sssd_conf = "/etc/sssd/sssd.conf"
    if exists(sssd_conf):
        utils.backup_(sssd_conf, name="sssd-original.conf")

    with open(sssd_conf, "w") as f:
        cnf.write(f)
        env_logger.debug("Configuration file for SSSD is updated "
                         "in  /etc/sssd/sssd.conf")
    chmod(sssd_conf, 0o600)


def create_softhsm2_config(card_dir):
    """
    Create SoftHSM2 configuration file in conf_dir. Same directory has to be used
    in setup-ca function, otherwise configuration file wouldn't be found causing
    the error. conf_dir expected to be in work_dir.
    """
    conf_dir = f"{card_dir}/conf"

    with open(f"{conf_dir}/softhsm2.conf", "w") as f:
        f.write(f"directories.tokendir = {card_dir}/tokens/\n"
                f"slots.removable = true\n"
                f"objectstore.backend = file\n"
                f"log.level = INFO\n")
        env_logger.debug(f"Configuration file for SoftHSM2 is created "
                         f"in {conf_dir}/softhsm2.conf.")


def create_virt_card_service(username, card_dir):
    """
    Create systemd service for for virtual smart card (virt_cacard.service).
    """
    path = f"/etc/systemd/system/virt_cacard_{username}.service"
    conf_dir = f"{card_dir}/conf"
    default = {
        "Unit": {
            "Description": f"virtual card for {username}",
            "Requires": "pcscd.service"},
        "Service": {
            "Environment": f'SOFTHSM2_CONF="{conf_dir}/softhsm2.conf"',
            "WorkingDirectory": card_dir,
            "ExecStart": "/usr/bin/virt_cacard >> /var/log/virt_cacard.debug 2>&1",
            "KillMode": "process"
        },
        "Install": {"WantedBy": "multi-user.target"}
    }
    cnf = ConfigParser()
    cnf.optionxform = str

    if exists(path):
        name = split(path)[1].split(".", 1)
        name = name[0] + "-original." + name[1]
        utils.backup_(path, name)

    with open(path, "w") as f:
        cnf.read_dict(default)
        cnf.write(f)
    env_logger.debug(f"Service file {path} for user '{username}' "
                     "is created.")


def read_env(item, *args, **kwargs):
    return config(item, *args, **kwargs)


def read_config(*items):
    """
    Read data from the configuration file and return require items or full
    content.

    Args:
        items: list of items to extracrt from the configuration file.
               If None, full contant would be returned

    Returns:
        list with required items
    """
    try:
        with open(read_env("CONF"), "r") as file:
            config_data = yaml.load(file, Loader=yaml.FullLoader)
            assert config_data, "Data are not loaded correctly."
    except FileNotFoundError as e:
        env_logger.error(".env file is not present. Try to rerun command"
                         "with --conf </path/to/conf.yaml> parameter")
        raise e

    if items is None:
        return config_data

    return_list = []
    for item in items:
        parts = item.split(".")
        value = config_data
        for part in parts:
            if value is None:
                env_logger.debug(
                    f"Key {part} not present in the configuration file. Skip.")
                return None

            value = value.get(part)
            if part == parts[-1]:
                return_list.append(value)

    return return_list if len(items) > 1 else return_list[0]


def setup_ca_(env_file):
    ca_dir = read_env("CA_DIR")
    env_logger.debug("Start setup of local CA")

    try:
        run(["bash", SETUP_CA, "--dir", ca_dir, "--env", env_file])
        env_logger.debug("Setup of local CA is completed")
    except CalledProcessError:
        env_logger.error("Error while setting up local CA")
        exit(1)


def setup_virt_card_(user: dict):
    """
    Call setup script fot virtual smart card

    Args:
        user: dictionary with user information
    """

    username, card_dir, passwd = user["name"], user["card_dir"], user["passwd"]
    cmd = ["bash", SETUP_VSC, "--dir", card_dir, "--username", username]
    if user["local"]:
        try:
            pwd.getpwnam(username)
        except KeyError:
            run(["useradd", username, "-m", ])
            env_logger.debug(f"Local user {username} is added to the system "
                             f"with a password {passwd}")
        finally:
            with Popen(['passwd', username, '--stdin'], stdin=PIPE,
                            stderr=PIPE, encoding="utf-8") as proc:
                proc.communicate(passwd)
            env_logger.debug(f"Password for user {username} is updated to {passwd}")
        create_cnf(username, conf_dir=join(card_dir, "conf"))
        cnf = ConfigParser()
        cnf.optionxform = str
        with open("/etc/sssd/sssd.conf", "r") as f:
            cnf.read_file(f)

        if f"certmap/shadowutils/{username}" not in cnf.sections():
            cnf.add_section(f"certmap/shadowutils/{username}")

        cnf.set(f"certmap/shadowutils/{username}", "matchrule",
                f"<SUBJECT>.*CN={username}.*")
        with open("/etc/sssd/sssd.conf", "w") as f:
            cnf.write(f)
        env_logger.debug("Match rule for local user is added to /etc/sssd/sssd.conf")
    try:
        if user["cert"]:
            cmd += ["--cert", user["cert"]]
        else:
            raise KeyError
        if user["key"]:
            cmd += ["--key", user["key"]]
        else:
            raise KeyError()
    except KeyError:
        ca_dir = read_env("CA_DIR")
        cmd += ["--ca", ca_dir]
        env_logger.debug(f"Key or certificate for user {username} "
                         f"is not present. New pair of key and cert will "
                         f"be generated by local CA from {ca_dir}")

    env_logger.debug(f"Start setup of virtual smart card for user {username} "
                     f"in {card_dir}")
    try:
        run(cmd, check=True, encoding="utf-8")
        env_logger.debug(f"Setup of virtual smart card for user {username} "
                         f"is completed")
    except CalledProcessError:
        env_logger.error("Error while setting up virtual smart card")
        exit(1)


def check_semodule():
    result = run(["semodule", "-l"], stdout=PIPE, stderr=PIPE, encoding="utf-8")
    if "virtcacard" not in result.stdout:
        env_logger.debug(
            "SELinux module for virtual smart cards is not present in the "
            "system. Installing...")
        conf_dir = join(read_env("CA_DIR"), 'conf')
        module = """
(allow pcscd_t node_t(tcp_socket(node_bind)))

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t(dir(read search)))"""
        with open(f"{conf_dir}/virtcacard.cil", "w") as f:
            f.write(module)
        try:
            run(
                ["semodule", "-i", f"{conf_dir}/virtcacard.cil"], check=True)
            env_logger.debug(
                "SELinux module for virtual smart cards is installed")
        except CalledProcessError:
            env_logger.error("Error while installing SELinux module "
                             "for virt_cacard")
            exit(1)

        try:
            run(["systemctl", "restart", "pcscd"], check=True)
            env_logger.debug("pcscd service is restarted")
        except CalledProcessError:
            env_logger.error("Error while resturting the pcscd service")
            exit(1)


def prepare_dir(dir_path, conf=True):
    Path(dir_path).mkdir(parents=True, exist_ok=True)
    env_logger.debug(f"Directory {dir_path} is created")
    if conf:
        Path(join(dir_path, "conf")).mkdir(parents=True, exist_ok=True)
        env_logger.debug(f"Directory {join(dir_path, 'conf')} is created")


def prep_tmp_dirs():
    """
    Prepair directory structure for test environment. All paths are taken from
    previously loaded env file.
    """
    paths = [read_env(path, cast=str) for path in ("CA_DIR", "TMP", "BACKUP")] + \
            [join(read_env("CA_DIR"), "conf")]
    for path in paths:
        prepare_dir(path, conf=False)


def install_ipa_client_(ip, passwd):
    env_logger.debug(f"Start installation of IPA client")
    args = ["bash", INSTALL_IPA_CLIENT, "--ip", ip, "--root", passwd]
    env_logger.debug(f"Aruments for script: {args}")
    try:
        run(args, check=True, encoding="utf-8")
        env_logger.debug("IPA client is configured on the system. "
                         "Don't forget to add IPA user by add-ipa-user command :)")
    except CalledProcessError:
        env_logger.error("Error while installing IPA client on local host")
        exit(1)


def add_ipa_user_(user):
    username, user_dir = user["name"], user["card_dir"]
    env_logger.debug(f"Adding user {username} to IPA server")
    ipa_admin_passwd, ipa_hostname = read_config("ipa_server_admin_passwd", "ipa_server_hostname")
    client = pipa.ClientMeta(ipa_hostname, verify_ssl=False)
    client.login("admin", ipa_admin_passwd)
    try:
        client.user_add(username, username, username, username )
    except pipa.exceptions.DuplicateEntry:
        env_logger.warn(f"User {username} already exists in the IPA server "
                        f"{ipa_hostname}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    prepare_dir(user_dir)

    with open(f"{user_dir}/private.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    try:
        cmd = ["openssl", "req", "-new", "-days", "365",
               "-nodes", "-key", f"{user_dir}/private.key", "-out",
               f"{user_dir}/cert.csr", "-subj", f"/CN={username}"]
        run(cmd, check=True, encoding="utf-8")
    except CalledProcessError:
        env_logger.error(f"Error while generating CSR for user {username}")
        exit(1)
    try:
        cmd = ["ipa", "cert-request", f"{user_dir}/cert.csr", "--principal",
               username, "--certificate-out", f"{user_dir}/cert.pem"]
        run(cmd, check=True, encoding="utf-8")
    except CalledProcessError:
        env_logger.error(f"Error while requesting the certificate for user "
                         f"{username} from IPA server")
        exit(1)

    env_logger.debug(f"User {username} is updated on IPA server. "
                     f"Cert and key stored into {user_dir}")


def setup_ipa_server_():
    run(["bash", SETUP_IPA_SERVER])


def general_setup(install_missing):
    args = ['bash', GENERAL_SETUP]
    if install_missing:
        args += ["--install-missing"]
    if config("READY", cast=int, default=0) != 1:
        check_semodule()
        try:
            run(args, check=True)
        except CalledProcessError:
            env_logger.error("Script for general setup is failed")
            exit(1)


def create_sc(sc_user):
    name, card_dir = sc_user["name"], sc_user["card_dir"]
    prepare_dir(card_dir)
    create_softhsm2_config(card_dir)
    env_logger.debug("SoftHSM2 configuration file is created in the "
                     f"{card_dir}/conf/softhsm2.conf")
    create_virt_card_service(name, card_dir)
    env_logger.debug(f"Start setup of virtual smart cards for local user {name}")
    setup_virt_card_(sc_user)
