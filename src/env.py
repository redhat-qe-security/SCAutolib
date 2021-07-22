from posixpath import join
import subprocess as subp
from configparser import ConfigParser
from os import mkdir
from os.path import exists, isfile, realpath, split

import yaml
from decouple import config
from pysftp import Connection
from SCAutolib import env_logger
from SCAutolib.src import (BACKUP, CERTS, CONF, CONF_DIR, CONFIG_DATA, KEYS,
                           SETUP_CA, SETUP_VSC, CA_DIR, check_env)

import utils


def create_kdc_config(sftp: Connection):
    check_env()
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


def create_krb_config(sftp: Connection = None):
    check_env()
    realm, username, ip_addr = read_config(
        "krb.realm_name", "krb.name", "krb.ip")

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
        env_logger.debug(
            f"Extensions file for KDC is created {CONF_DIR}/extensions.kdc")

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

    krb_conf = "/etc/krb5.conf"
    exist = sftp.exists(krb_conf) if sftp is not None else exists(krb_conf)
    if exist:
        utils.backup_(krb_conf, "krb5-original.conf", sftp)

    cnf = ConfigParser()
    cnf.optionxform = str
    content = {
        "logging": {
            "default": "FILE:/var/log/krb5libs.log",
            "kdc": "FILE:/var/log/krb5kdc.log",
            "admin_server": "FILE:/var/log/kadmind.log"
        },
        "libdefaults": {
            "dns_lookup_realm": "false",
            "dns_lookup_kdc": "false",
            "rdns": "false",
            "ticket_lifetime": "24h",
            "renew_lifetime": "7d",
            "forwardable": "true",
            "default_ccache_name": "KEYRING:persistent: % {uid}",
            "default_realm": realm,
        },
        "realms": {
            realm: """{
        pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
        pkinit_cert_match = <KU>digitalSignature
        kdc = krb-server.sctesting.redhat.com
        admin_server = krb-server.sctesting.redhat.com
        pkinit_kdc_hostname = krb-server.sctesting.redhat.com
        }"""
        },
        "domain_realm": {
            ".sctesting.redhat.com": realm,
            ".ctesting.redhat.com": realm,
        },
    }

    # NOTE: this may be not needed if IPA would be used
    if sftp:
        hostname = read_config("krb.server_name")
        domain_name = hostname.split(".", 1)[1]

        content["realms"] = {realm: "{\n"
                                    f"""kdc = {hostname}:88
                                        admin_server = {hostname}"
                                        default_domain = {domain_name}"
                                        pkinit_anchors = FILE:/var/kerberos/krb5kdc/kdc-ca.pem\n"""
                                    "\t}\n"}
    else:
        content["appdefaults"] = {
            "pam": """{
        debug = true
        ticket_lifetime = 1h
        renew_lifetime = 3h
        forwardable = true
        krb4_convert = false
        }"""
        }

    cnf.read_dict(content)

    if sftp:
        with sftp.open(krb_conf, "w") as f:
            f.write("includedir /etc/krb5.conf.d/")
            cnf.write(f)
            env_logger.debug("File /etc/krb5.conf is updated.")
    else:
        with open(krb_conf, "w") as f:
            f.write("includedir /etc/krb5.conf.d/")
            cnf.write(f)
            env_logger.debug("File /etc/krb5.conf is updated.")

        subp.run(
            ["setsebool", "-P", "sssd_connect_all_unreserved_ports", "on"], check=True)
        env_logger.debug(
            "SELinux boolean sssd_connect_all_unreserved_ports is set to ON")

        krb_ip_addr = read_config("krb.ip")
        with open("/etc/hosts", "a") as f:
            f.write(f"{krb_ip_addr} krb-server.sctesting.redhat.com\n")
            env_logger.debug(
                "IP address of kerberos server is added to /etc/hosts file")


def prep_tmp_dirs():
    """
    Prepair directory structure for test environment. All paths are taken from
    previously loaded env file.
    """
    for dir_env_var in ("CA_DIR", "TMP", "BACKUP", "CONF_DIR"):
        dir_path = config(dir_env_var, cast=str)
        if not exists(dir_path):
            mkdir(dir_path)


def create_cnf(user):
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
    # conf_dir =
    with open(f"{conf_dir}/req_{user}.cnf", "w") as f:
        f.write(user_cnf)
        env_logger.debug(f"Configuration file for CSR for user {user} is created "
                         f"{conf_dir}/req_{user}.cnf")


def create_sssd_config(local_user: str = None, krb_user: str = None):
    """
    Update the content of the sssd.conf file. If file exists, it would be store
    to the backup folder and content in would be edited for testing purposes.
    If file doesn't exist, it would be created and filled with default options.

    Args:
        local_user: username for local user with smart card to add the match rule.
        krb_user: username for kerberos user with smart card to add the match rule.
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

    if exists("/etc/sssd/sssd.conf"):
        utils.backup_("/etc/sssd/sssd.conf", name="sssd-original.conf")

    if local_user:
        cnf[f"certmap/shadowutils/{local_user}"] = {
            f"#<[certmap/shadowutils/{local_user}]>": None,
            "matchrule": f"<SUBJECT>.*CN={local_user}.*"}

    with open("/etc/sssd/sssd.conf", "w") as f:
        cnf.write(f)
        env_logger.debug("Configuration file for SSSD is updated "
                         "in  /etc/sssd/sssd.conf")


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
                         f"in {CONF_DIR}/softhsm2.conf.")


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
        env_logger.debug(
            f"Service file {path} for user '{username}' is created.")


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
    with open(config("CONF"), "r") as file:
        config_data = yaml.load(file, Loader=yaml.FullLoader)
        assert config_data, "Data are not loaded correctly."

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
                break

            value = value.get(part)
            if part == parts[-1]:
                return_list.append(value)

    return return_list if len(items) > 1 else return_list[0]


def setup_ca_(env_file):
    work_dir = read_config("ca_dir")
    env_logger.debug("Start setup of local CA")

    out = subp.run(["bash", SETUP_CA,
                    "--dir", work_dir,
                    "--env", env_file])
    assert out.returncode == 0, "Something break in setup script"

    env_logger.debug("Setup of local CA is completed")


def setup_virt_card_(user):
    """
    Call setup script fot virtual smart card

    Args:
        env_file: Path to .env file
    """
    check_env()
    ca_dir, card_dir = read_config("work_dir", f"{user}.card_dir")
    cmd = ["bash", SETUP_VSC, "--dir", f"/root/{user}"]
    username = read_config(f"{user}.name")
    cmd = ["bash", SETUP_VSC, "--dir", card_dir]
    if user == "local_user":
        cmd += ["--ca", ca_dir, "--username", username]

    env_logger.debug(f"Start setup of virtual smart card for user {username}")
    out = subp.run(cmd, check=True)

    assert out.returncode == 0, "Something break in setup script :("
    env_logger.debug("Setup of local CA is completed")


def check_semodule():
    result = subp.run(["semodule", "-l"], capture_output=True)
    if "virtcacard" not in result.output:
        env_logger.debug(
            "SELinux module for virtual smart cards is not present in the system.")
        work_dir = config("CA_DIR")
        module = """
(allow pcscd_t node_t(tcp_socket(node_bind)))

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t(dir(read search)))"""
        with open(f"{work_dir}/conf/virtcacard.cil", "w") as f:
            f.write(module)
        subp.run(
            ["semodule", "-i", f"{work_dir}/conf/virtcacard.cil"], check=True)
        env_logger.debug(
            "SELinux module for virtual smart cards is installed")


def prepare_dir(dir, conf=True):
    mkdir(dir)
    if conf:
        mkdir(join(dir, "conf"))
