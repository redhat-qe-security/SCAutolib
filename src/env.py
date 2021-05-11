import logging
from os.path import (exists, realpath, isdir,
                     isfile, dirname, abspath)
from os import mkdir
import click
import yaml
import subprocess as subp
from shutil import copytree, copy
from re import match
from decouple import config
import SCAutolib.src.utils as utils

log = logging.getLogger("env")

# TODO add docs about parameters
DIR_PATH = dirname(abspath(__file__))
SETUP_CA = f"{DIR_PATH}/env/setup_ca.sh"
SETUP_VSC = f"{DIR_PATH}/env/setup_virt_card.sh"
CLEANUP_CA = f"{DIR_PATH}/env/cleanup_ca.sh"
WORK_DIR = None
TMP = f"{WORK_DIR}/tmp"
CONF_DIR = f"{WORK_DIR}/conf"
KEYS = f"{TMP}/keys"
CERTS = f"{TMP}/certs"
BACKUP = f"{TMP}/backup"
CONFIG_DATA = None  # for caching configuration data


@click.group()
def cli():
    pass


@click.command()
@click.option("--conf", "-c", type=click.Path(),
              help="Path to YAML file with configurations.", required=False)
@click.option("--work-dir", "-w", type=click.Path(),
              help="Absolute path to working directory.",
              required=False, default=DIR_PATH)
@click.option("--env", "-e", type=click.Path(),
              help="Absolute path to .env file with environment varibles to be "
                   "used in the library.", required=False, default=None)
def prepair(conf, work_dir, env):

    _load_env(env, work_dir)

    _prep_tmp_dirs()
    log.debug("tmp directories are created")

    usernames = _read_config(conf, items=["variables.local_user.name",
                                          "variables.krb_user.name"])
    _create_sssd_config(*usernames)
    log.debug("SSSD configuration file is updated")

    _create_softhsm2_config()
    log.debug("SoftHSM2 configuration file is created in the "
              f"{CONF_DIR}/softhsm2.conf")
    #
    # _create_virtcacard_configs()
    # log.debug("Configuration files for virtual smart card are created.")
    # # TODO: create .cnf files for certificates

    # setup_ca()
    #
    # setup_virt_card()


def _load_env(env, work_dir):
    global WORK_DIR
    global CONF_DIR
    global BACKUP

    if env is None:
        env = f"{DIR_PATH}/.env"
        with open(env, "w") as f:
            f.write(f"WORK_DIR = {work_dir}\n")
            f.write(f"TMP = {work_dir}/tmp\n")
            f.write(f"CONF_DIR = {work_dir}/conf\n")
            f.write(f"KEYS = {work_dir}/tmp/keys\n")
            f.write(f"CERTS = {work_dir}/tmp/certs\n")
            f.write(f"BACKUP = {work_dir}/tmp/backup\n")
    else:
        # .env file should be near source file because it this env is loaded
        # in other source files
        copy(env, DIR_PATH)

    WORK_DIR = work_dir
    CONF_DIR = config("CONF_DIR", cast=str)
    BACKUP = config("BACKUP", cast=str)


def _prep_tmp_dirs():
    """
    Prepair directory structure for test environment. All paths are taken from
    previously loaded env file.
    """
    for dir_env_var in ("WORK_DIR", "TMP", "KEYS", "CERTS", "BACKUP", "CONF_DIR"):
        dir_path = config(dir_env_var, cast=str)
        if not exists(dir_path):
            mkdir(dir_path)


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
    if exists("/etc/sssd/sssd.conf"):
        # utils._backup("/etc/sssd/sssd.conf", name="sssd-original.conf", env=True)
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
            # FIXME: add rule for kerberos user
            # content.append(rule)
    else:
        content = ["[sssd]\n",
                   "debug_level = 9\n",
                   "services = nss, pam\n",
                   "domains = shadowutils\n",
                   "#<[sssd]>\n",
                   "\n[nss]\n",
                   "debug_level = 9\n",
                   "#<[nss]>\n",
                   "\n[pam]\n",
                   "debug_level = 9\n",
                   "pam_cert_auth = True\n",
                   "#<[pam]>\n",

                   "\n[domain/shadowutils]\n",
                   "debug_level = 9\n",
                   "id_provider = files\n",
                   "#<[domain/shadowutils]>\n"]
        if local_user:
            content.append(f"\n[certmap/shadowutils/{local_user}]\n"
                           f"matchrule = <SUBJECT>.*CN = {local_user}.*\n"
                           f"#<[certmap/shadowutils/{local_user}]>\n")
        if krb_user:
            pass
        # FIXME: add rule for kerberos user

    with open("/etc/sssd/sssd.conf", "w") as f:
        f.write("".join(content))


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
    with open(f"{CONF_DIR}/softhsm2.conf", "w") as f:
        f.write(f"directories.tokendir = {WORK_DIR}/tokens/\n"
                f"slots.removable = true\n"
                f"objectstore.backend = file\n"
                f"log.level = INFO\n")


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
        utils._backup(module_path, "virtcacard.cil-original")

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
    log.debug(
        f"Service file {service_path} for virtual smart card is created.")
    with open(module_path, "w") as f:
        f.write("""(allow pcscd_t node_t (tcp_socket (node_bind)));

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t (dir """)

    log.debug(f"SELinux module create {module_path}")


def _read_config(config, items: [str] = None) -> dict or list:
    """
    Read data from the configuration file and return require items or full
    content.

    Args:
        config: path to configuration file
        items: list of items to extracrt from the configuration file.
               If None, full contant would be returned

    Returns: dictionary with full contant or list with required items
    """
    global CONFIG_DATA
    if CONFIG_DATA is None:
        with open(config, "r") as file:
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
                log.debug(
                    f"Key {part} not present in the configuration file. Skip.")
                break
    return return_list


@click.command()
@click.option("--work-dir", "-w", type=click.Path(), help="Path to working directory")
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def setup_ca(work_dir, conf):
    """
    Setup local CA

    :param work_dir: Path to working directory
    :param conf: Path to YAML file with configurations
    """
    assert exists(work_dir), f"Path {work_dir} is not exist"
    assert isdir(work_dir), f"{work_dir} is not a directory"
    assert exists(realpath(conf)), f"File {conf} is not exist"
    assert isfile(realpath(conf)), f"{conf} is not a file"

    log.debug("Start setup of local CA")

    src, user = _read_config(conf, items=["configs.dir", "variables"])
    conf_dir = f"{work_dir}/conf"
    copytree(realpath(src), conf_dir)
    # user = data["variables"]["user"]
    print(work_dir)
    out = subp.run(["bash", SETUP_CA, "--dir", work_dir,
                    "--username", user["name"],
                    "--userpasswd", user["passwd"],
                    "--pin", user["pin"],
                    "--conf-dir", conf_dir])
    assert out.returncode == 0, "Something break in setup playbook :("
    log.debug("Setup of local CA is completed")


@click.command()
@click.option("--conf-dir", "-C", type=click.Path(), help="Directory with configuration files")
@click.option("--work-dir", "-w", type=click.Path(), help="Working directory")
def setup_virt_card(conf_dir, work_dir):
    """
    Setup virtual smart card. Has to be run after configuration of the local CA.

    :param conf_dir: Directory with configuration files
    :param work_dir: Working directory
    """
    assert exists(conf_dir), f"Path {conf_dir} is not exist"
    assert isdir(conf_dir), f"{conf_dir} Not a directory"
    assert exists(work_dir), f"Path {work_dir} is not exist"
    assert isdir(work_dir), f"{work_dir} Not a directory"

    log.debug("Start setup of local CA")
    out = subp.run(["bash", SETUP_VSC, "-c", conf_dir, "-w", work_dir])

    assert out.returncode == 0, "Something break in setup playbook :("
    log.debug("Setup of local CA is completed")


@click.command()
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def cleanup_ca(conf):
    """
    Cleanup the host after configuration of the testing environment.
    """
    log.debug("Start cleanup of local CA")
    with open(conf, "r") as file:
        data = yaml.load(file, Loader=yaml.FullLoader)
    username = data["variables"]["user"]["name"]
    out = subp.run(
        ["bash", CLEANUP_CA, "--username", username])

    assert out.returncode == 0, "Something break in setup script :("
    log.debug("Cleanup of local CA is completed")


cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(cleanup_ca)
cli.add_command(prepair)

if __name__ == "__main__":
    cli()
