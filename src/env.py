from os.path import (exists, realpath, isfile, dirname, abspath, join)
from os import mkdir
import click
import yaml
import subprocess as subp
from shutil import copy
from re import match
from decouple import config
import utils as utils
from SCAutolib import env_logger

# TODO add docs about parameters
DIR_PATH = dirname(abspath(__file__))
SETUP_CA = f"{DIR_PATH}/env/setup_ca.sh"
SETUP_VSC = f"{DIR_PATH}/env/setup_virt_card.sh"
CLEANUP_CA = f"{DIR_PATH}/env/cleanup_ca.sh"
WORK_DIR = f"{DIR_PATH}/virt_card"
TMP = f"{WORK_DIR}/tmp"
CONF_DIR = f"{WORK_DIR}/conf"
KEYS = f"{TMP}/keys"
CERTS = f"{TMP}/certs"
BACKUP = f"{TMP}/backup"
CONFIG_DATA = None  # for caching configuration data


@click.group()
def cli():
    pass


def check_env():
    def wrapper(fnc):
        def inner(*args, **kwargs):
            global BACKUP
            global KEYS
            global CERTS
            if BACKUP is None:
                BACKUP = config("BACKUP")
            if KEYS is None:
                KEYS = config("KEYS")
            if CERTS is None:
                KEYS = config("CERTS")
            if TMP is None:
                KEYS = config("TMP")
            fnc(*args, **kwargs)

        return inner

    return wrapper


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
def prepair(setup, conf, work_dir, env_file):
    """
    Prepair the whole test envrionment including temporary directories, necessary
    configuration files and services. Also can automaticaly run setup for local
    CA and virtual smart card.

    Args:
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
                                          "krb_user.name"])
    _create_sssd_config(*usernames)
    env_logger.debug("SSSD configuration file is updated")

    _create_softhsm2_config()
    env_logger.debug("SoftHSM2 configuration file is created in the "
                     f"{CONF_DIR}/softhsm2.conf")

    _create_virtcacard_configs()
    env_logger.debug("Configuration files for virtual smart card are created.")

    _creat_cnf(usernames)

    if setup:
        _setup_ca(conf, env_file)

        _setup_virt_card(env_file)


def _load_env(env_file, work_dir=join(DIR_PATH, "virt_card")) -> str:
    """
    Create .env near source files of the libarary. In .env file following
    variables expected to be present: WORK_DIR, CONF_DIR, TMP, KEYS, CERTS, BACKUP.
    Deployment process would relay on this variables.

    Args:
        env_file:  path to already existing .env file. If given, then it would be just copied to the library.
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
            f.write(f"KEYS={join(work_dir, 'tmp','keys')}\n")
            f.write(f"CERTS={join(work_dir, 'tmp','certs')}\n")
            f.write(f"BACKUP={join(work_dir, 'tmp','backup')}\n")
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
        with open("/etc/sssd/sssd.conf", "r") as f:
            content = f.readlines()
        for index, line in enumerate(content):
            if match(r"^\[(.*)]\n$", line):
                content[index] = line + holder.format(holder=line.rstrip("\n"))
        if local_user:
            rule = f"\n[certmap/shadowutils/{local_user}]\n" \
                   f"matchrule = <SUBJECT>.*CN={local_user}.*\n" \
                   f"#<[certmap/shadowutils/{local_user}]>\n"
            content.append(rule)

        if krb_user:
            pass
            # TODO: add rule for kerberos user
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

        if local_user:
            content.append(f"\n[certmap/shadowutils/{local_user}]\n"
                           f"#<[certmap/shadowutils/{local_user}]>\n"
                           f"matchrule = <SUBJECT>.*CN={local_user}.*\n")
        if krb_user:
            pass
            # TODO: add rule for kerberos user

    with open("/etc/sssd/sssd.conf", "w") as f:
        f.write("".join(content))
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


def _read_config(conf, items: [str] = None) -> list:
    """
    Read data from the configuration file and return require items or full
    content.

    Args:
        conf: path to configuration file
        items: list of items to extracrt from the configuration file.
               If None, full contant would be returned

    Returns: dictionary with full contant or list with required items
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
            try:
                if value is None:
                    raise KeyError
                value = value.get(part)

                if part == parts[-1]:
                    return_list.append(value)
            except KeyError:
                env_logger.debug(
                    f"Key {part} not present in the configuration file. Skip.")
                break
    return return_list


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
    f"""
    Setup local CA.

    Args:
        conf: Path to YAML file with configurations
        work_dir:Path to working directory. By default is {join(DIR_PATH, 'virt_card')}
        env_file: Path to .env file with specified variables
    """

    env_path = _load_env(env_file, work_dir)
    _setup_ca(conf, env_path)


@check_env()
def _setup_ca(conf, env_file):
    assert exists(realpath(conf)), f"File {conf} is not exist."
    assert isfile(realpath(conf)), f"{conf} is not a file."

    env_logger.debug("Start setup of local CA")

    user = _read_config(conf, items=["local_user"])[0]
    out = subp.run(["bash", SETUP_CA,
                    "--username", user["name"],
                    "--userpasswd", user["passwd"],
                    "--pin", user["pin"],
                    "--env", env_file])
    assert out.returncode == 0, "Something break in setup playbook :("
    env_logger.debug("Setup of local CA is completed")


@click.command()
@click.option("--env", type=click.Path(), required=False, default=None,
              help="Path to .env file with specified variables")
@click.option("--work-dir", type=click.Path(), required=False,
              default=join(DIR_PATH, "virt_card"))
def setup_virt_card(env, work_dir):
    """
    Setup virtual smart card. Has to be run after configuration of the local CA.

    :param conf_dir: Directory with configuration files
    :param work_dir: Working directory
    """
    env_path = _load_env(env, work_dir)
    _setup_virt_card(env_path)


@check_env()
def _setup_virt_card(env_file):

    env_logger.debug("Start setup of local CA")
    out = subp.run(["bash", SETUP_VSC, "-c", CONF_DIR, "-e", env_file])

    assert out.returncode == 0, "Something break in setup playbook :("
    env_logger.debug("Setup of local CA is completed")


@click.command()
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def cleanup_ca(conf):
    """
    Cleanup the host after configuration of the testing environment.

    Args:
        conf: path to configuraion file in YAML format
    """
    env_logger.debug("Start cleanup of local CA")

    username = _read_config(conf, ["local_user.name"])[0]
    # TODO: check after adding kerberos user that everything is also OK
    out = subp.run(
        ["bash", CLEANUP_CA, "--username", username])

    assert out.returncode == 0, "Something break in cleanup script :("
    env_logger.debug("Cleanup of local CA is completed")


cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(cleanup_ca)
cli.add_command(prepair)

if __name__ == "__main__":
    cli()
