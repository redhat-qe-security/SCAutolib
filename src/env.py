import yaml
import utils as utils
import subprocess as subp
from os.path import (exists, realpath, isfile, split)
from os import mkdir
from pysftp import Connection
from decouple import config
from configparser import ConfigParser
from SCAutolib import env_logger
from SCAutolib.src import (check_env, KEYS, CERTS, WORK_DIR, CONF_DIR, BACKUP,
                           CONF, CONFIG_DATA, SETUP_CA, SETUP_VSC)


def create_kdc_config(sftp: Connection):
    check_env()
    realm = read_config("krb.realm_name")
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
    realm, username, ip_addr = read_config("krb.realm_name", "krb.name", "krb.ip")

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

        subp.run(["setsebool", "-P", "sssd_connect_all_unreserved_ports", "on"], check=True)
        env_logger.debug("SELinux boolean sssd_connect_all_unreserved_ports is set to ON")

        krb_ip_addr = read_config("krb.ip")
        with open("/etc/hosts", "a") as f:
            f.write(f"{krb_ip_addr} krb-server.sctesting.redhat.com\n")
            env_logger.debug("IP address of kerberos server is added to /etc/hosts file")


def generate_krb_certs():
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


def prep_tmp_dirs():
    """
    Prepair directory structure for test environment. All paths are taken from
    previously loaded env file.
    """
    for dir_env_var in ("WORK_DIR", "TMP", "KEYS", "CERTS", "BACKUP", "CONF_DIR"):
        dir_path = config(dir_env_var, cast=str)
        if not exists(dir_path):
            mkdir(dir_path)


def creat_cnf(user_list: [], ca: bool = True):
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
    cnf.optionxform = str  # Needed for correct parsing of upercase words
    default = {
        "sssd": {"#<[sssd]>": None,
                 "debug_level": "9",
                 "services": "nss, pam",
                 "domains": "shadowutils,ldap"},
        "nss": {"#<[nss]>": None,
                "debug_level": "9"},
        "pam": {"#<[pam]>": None,
                "debug_level": "9",
                "pam_cert_auth": "True"},
        "domain/shadowutils": {"#<[domain/shadowutils]>": None,
                               "debug_level": "9",
                               "id_provider": "files"},
    }

    if exists("/etc/sssd/sssd.conf"):
        utils.backup_("/etc/sssd/sssd.conf", name="sssd-original.conf")
        # TODO: make more strict checking of the content in the file
        cnf.read("etc/sssd/sssd.conf")
        for section in cnf.sections():
            cnf.set(section, f"#<[{section}]>")
    else:
        cnf.read_dict(default)

    if local_user:
        cnf[f"certmap/shadowutils/{local_user}"] = {
            f"#<[certmap/shadowutils/{local_user}]>": None,
            "matchrule": f"<SUBJECT>.*CN={local_user}.*"}

    if krb_user:
        try:
            krb_server_name, krb_realm = read_config("krb.server_name", "krb.realm_name")
        except Exception as e:
            env_logger.error(e)
            raise Exception("Can't get server_name and realm_name fields from "
                            "krb section. Check parent exception in logs")

        if "krb5" not in cnf["sssd"]["domains"].replace(" ", "").split(","):
            cnf["sssd"]["domains"] = cnf["sssd"]["domains"] + ",krb5"

        cnf["domain/krb5"] = {"id_provider": "ldap",
                              "auth_provider": "krb5",
                              "krb5_server": krb_server_name,
                              "krb5_realm": krb_realm}
        cnf[f"certmap/krb5/{krb_user}"] = {f"#<[certmap/krb5/{krb_user}]>": None,
                                           "maprule": f"(uid={krb_user})"}

    with open("/etc/sssd/sssd.conf", "w") as f:
        cnf.write(f)
        env_logger.debug("Configuration file for SSSD is updated "
                         "in  /etc/sssd/sssd.conf")


def create_softhsm2_config():
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


def create_virtcacard_configs():
    """
    Create systemd service (virt_cacard.service) and semodule (virtcacard.cil)
    for virtual smart card.
    """
    # TODO create virt_cacard.service
    items = [
        {"path": "/etc/systemd/system/virt_cacard.service",
         "user": "local_user",
         "work_dir": WORK_DIR,
         "conf_dir": CONF_DIR},
        {"path": "/etc/systemd/system/virt_krb.service",
         "user": "krb_user",
         "work_dir": WORK_DIR,
         "conf_dir": CONF_DIR}]
    default = {
        "Unit": {
            "Description": "virtual card for {name}",
            "Requires": "pcscd.service"},
        "Service": {
            "Environment": 'SOFTHSM2_CONF="{conf_dir}/softhsm2.conf"',
            "WorkingDirectory": "{work_dir}",
            "ExecStart": "/usr/bin/virt_cacard >> /var/log/virt_cacard.debug 2>&1",
            "KillMode": "process"
        },
        "Install": {"WantedBy": "multi-user.target"}
    }
    cnf = ConfigParser()
    cnf.optionxform = str
    module_path = f"{CONF_DIR}/virtcacard.cil"

    for path in [items[0]["path"], items[1]["path"], module_path]:
        if exists(path):
            name = split(path)[1].split(".", 1)
            name = name[0] + "-original." + name[1]
            utils.backup_(path, name)

    for item in items:
        with open(item["path"], "w") as f:
            cnf.read_dict(default)
            cnf["Unit"]["Description"] = cnf["Unit"]["Description"].format(name=item["user"])
            cnf["Service"]["Environment"] = cnf["Service"]["Environment"].format(conf_dir=item["conf_dir"])
            cnf["Service"]["WorkingDirectory"] = cnf["Service"]["WorkingDirectory"].format(work_dir=item["work_dir"])
            cnf.write(f)
            env_logger.debug(
                f"Service file {item['path']} for virtual smart card with {item['user']} is created.")
    # TODO: Create service for krb user

    with open(module_path, "w") as f:
        f.write("""(allow pcscd_t node_t (tcp_socket (node_bind)));

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t (dir (read search)));""")

    env_logger.debug(f"SELinux module create {module_path}")


def read_config(*items) -> list or str:
    """
    Read data from the configuration file and return require items or full
    content.

    Args:
        items: list of items to extracrt from the configuration file.
               If None, full contant would be returned

    Returns:
        list with required items
    """
    check_env()
    global CONFIG_DATA
    if CONFIG_DATA is None:
        with open(CONF, "r") as file:
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

    user = read_config("local_user")
    if user is not dict:
        raise Exception("Field 'local_user' is not present in the configuraion "
                        "file or it is not a dictionary")
    out = subp.run(["bash", SETUP_CA,
                    "--username", user["name"],
                    "--userpasswd", user["passwd"],
                    "--pin", user["pin"],
                    "--env", env_file])
    assert out.returncode == 0, "Something break in setup playbook :("
    env_logger.debug("Setup of local CA is completed")


def setup_virt_card(env_file):
    """
    Call setup scritp fro virtual smart card

    Args:
        env_file: Path to .env file
    """
    check_env()
    env_logger.debug("Start setup of local CA")
    out = subp.run(["bash", SETUP_VSC, "-c", CONF_DIR, "-e", env_file], check=True)

    assert out.returncode == 0, "Something break in setup script :("
    env_logger.debug("Setup of local CA is completed")
