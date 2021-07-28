from posixpath import join
import subprocess as subp
from subprocess import PIPE, run, Popen
from configparser import ConfigParser
from os.path import (exists, split)
from os import chmod
from pathlib import Path
from crypt import crypt

import yaml
from decouple import config
from pysftp import Connection
from SCAutolib import env_logger
from SCAutolib.src import *

import utils


def create_kdc_config(sftp: Connection):
    realm = read_config("krb.realm_name")
    kdc_conf = "/var/kerberos/krb5kdc/kdc.conf"
    env_logger.debug(f"Realm name: {realm}")

    sftp.get(kdc_conf, f"{BACKUP}/kdc-original.conf")
    env_logger.debug(
        f"File {kdc_conf} is copied to {BACKUP}/kdc-original.conf")

    cnf = ConfigParser()
    cnf.optionxform = str
    with sftp.open(kdc_conf, "r") as f:
        cnf.read_file(f, source="kdc.conf")

        for sec in ["kdcdefaults", "realms"]:
            if not cnf.has_section(sec):
                env_logger.debug(
                    f"Section {sec} is not present in {kdc_conf}.")
                cnf.add_section(sec)
                env_logger.debug(f"Section {sec} in {kdc_conf} is created.")
        present = True
        if not cnf.has_option("realms", realm):
            env_logger.debug(
                f"Option {realm} is not present in realms section in {kdc_conf}.")
            cnf.set("realms", realm, "{}")
            env_logger.debug(
                f"Option {realm} is created in realms section in {kdc_conf}.")
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
            env_logger.debug(
                f"Option {realm} presents in realms section in {kdc_conf}.")
            d = {}
            tmp = cnf.get("realms", realm) \
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


def create_cnf(user, conf_dir=None):
    """
    Create configuration files for OpenSSL to generate certificates and requests.
    """
    if user == "ca":
        ca_dir = config("CA_DIR")
        conf_dir = join(ca_dir, "conf")
        ca_cnf = f"""[ ca ]
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
        if conf_dir is None:
            raise Exception(f"No conf directory is provided for user {user}")
        with open(f"{conf_dir}/ca.cnf", "w") as f:
            f.write(ca_cnf)
            env_logger.debug(
                f"Configuration file for local CA is created {conf_dir}/ca.cnf")
        return

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
    with open(f"{conf_dir}/req_{user}.cnf", "w") as f:
        f.write(user_cnf)
        env_logger.debug(f"Configuration file for CSR for user {user} is created "
                         f"{conf_dir}/req_{user}.cnf")


def create_sssd_config(local_user: str = None):
    """
    Update the content of the sssd.conf file. If file exists, it would be store
    to the backup folder and content in would be edited for testing purposes.
    If file doesn't exist, it would be created and filled with default options.

    Args:
        local_user: username for local user with smart card to add the match rule.
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

    out = subp.run(["bash", SETUP_CA,
                    "--dir", ca_dir,
                    "--env", env_file])
    assert out.returncode == 0, "Something break in setup script"

    env_logger.debug("Setup of local CA is completed")


def setup_virt_card_(user: dict):
    """
    Call setup script fot virtual smart card

    Args:
        user: dictionary with user information
    """

    username, card_dir, passwd = user["name"], user["card_dir"], user["passwd"]
    cmd = ["bash", SETUP_VSC, "--dir", card_dir, "--username", username]
    if user["local"]:
        if subp.run(["id", username]).returncode != 0:
            enc_passwd = crypt(passwd, '22')
            subp.run(["useradd", username, "-m", "-p", enc_passwd])
            env_logger.debug(f"Local user {username} is added to the system "
                             f"with a password {passwd}")
        else:
            with subp.Popen(['passwd', username, '--stdin'], stdin=subp.PIPE,
                            stderr=subp.PIPE, encoding="utf-8") as proc:
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
            raise KeyError
    except KeyError:
        ca_dir = read_env("CA_DIR")
        cmd += ["--ca", ca_dir]
        env_logger.debug(f"Key or certificate for user {username} "
                         f"is not present. New pair of key and cert will "
                         f"be generated by local CA from {ca_dir}")

    env_logger.debug(f"Start setup of virtual smart card for user {username} "
                     f"in {card_dir}")
    out = subp.run(cmd, check=True, encoding="utf-8")
    assert out.returncode == 0, "Something break in setup script of " \
                                "virtual smart card :("
    env_logger.debug(f"Setup of virtual smart card for user {username} "
                     f"is completed")


def check_semodule():
    result = subp.run(["semodule", "-l"], stdout=subp.PIPE, stderr=subp.PIPE,
                      encoding="utf-8")
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
        subp.run(
            ["semodule", "-i", f"{conf_dir}/virtcacard.cil"], check=True)
        env_logger.debug(
            "SELinux module for virtual smart cards is installed")


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


def install_ipa_client_(ip):
    env_logger.debug(f"Start installation of IPA client")
    args = ["bash", INSTALL_IPA_CLIENT, "--ip", ip]
    env_logger.debug(f"Aruments for script: {args}")
    run(args, check=True, encoding="utf-8")
    env_logger.debug("IPA client is configured on the system. "
                     "Don't forget to add IPA user by add-ipa-user command :)")


def add_ipa_user_(user):
    username, user_dir = user["name"], user["card_dir"]
    env_logger.debug(f"Adding user {username} to IPA server")
    args = ["bash", ADD_IPA_CLIENT, "--username", username, "--dir", user_dir]
    run(args, check=True, encoding="utf-8")
    env_logger.debug(f"User {username} is added to IPA server. "
                     f"Cert and key stored into {user_dir}")


def setup_ipa_server_():
    run(["bash", SETUP_IPA_SERVER])
