import click
from time import sleep
import paramiko
from pysftp import Connection, CnOpts

from SCAutolib.src import load_env, DIR_PATH, CLEANUP_CA
from SCAutolib.src.env import *


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
    env_file = load_env(env_file, conf, work_dir)
    print("Path to config file is: ", conf)

    prep_tmp_dirs()
    env_logger.debug("tmp directories are created")

    usernames = read_config("local_user.name", "krb.name")
    create_sssd_config(*usernames)
    env_logger.debug("SSSD configuration file is updated")

    create_softhsm2_config()
    env_logger.debug("SoftHSM2 configuration file is created in the "
                     f"{CONF_DIR}/softhsm2.conf")

    create_virtcacard_configs()
    env_logger.debug("Configuration files for virtual smart card are created.")

    creat_cnf(usernames)

    create_krb_config()

    if setup:
        setup_ca(conf, env_file)
        setup_virt_card(env_file)

    if krb:
        # setup_krb_server(conf)
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
    env_path = load_env(env_file, work_dir)
    setup_ca(conf, env_path)


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
    env_path = load_env(env, work_dir)
    setup_virt_card(env_path)


@click.command()
# @click.option("--conf", "-c", type=click.Path(), required=True,
#               help="Path to YAML file with configurations")
def setup_krb_client():
    check_env()
    pkgs = ["krb5-libs", "krb5-workstation", "ccid", "opensc", "esc", "pcsc-lite",
            "pcsc-lite-libs", "authconfig", "gdm", "nss-pam-ldapd", "oddjob",
            "oddjob-mkhomedir"]
    subp.run(["dnf", "install", *pkgs, "-y"], check=True)
    env_logger.debug(f"Packages for Kerberos client are installed")

    subp.run(["yum", "groupinstall", "'Smart Card Support'", "-y"])
    env_logger.debug(f"Smart Card Support group is installed")
    create_krb_config()

    sleep(3)
    utils.restart_service("sssd")
    sleep(3)
    subp.run(["systemctl", "enable", "--now", "oddjobd.service"], check=True)


@click.command()
@click.option("--conf", "-c", type=click.Path(), required=True)
def setup_krb_server(conf):
    check_env()

    create_krb_config()

    cert, key = generate_krb_certs()
    env_logger.debug(f"KDC certificat: {cert}")
    env_logger.debug(f"KDC private key: {key}")
    krb_ip, krb_root_passwd = read_config("krb.ip", "krb.root_passwd")

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

        create_kdc_config(sftp)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(krb_ip, 22, "root", krb_root_passwd)
    env_logger.debug(f"SSH connectin to {krb_ip} is istablished")
    ssh.exec_command("systemctl restart krb5kdc")
    env_logger.debug(f"Service krb5kdc on {krb_ip} is restarted")
    # TODO: check on errors


@click.command()
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def cleanup_ca():
    """
    Cleanup the host after configuration of the testing environment.
    """
    check_env()
    env_logger.debug("Start cleanup of local CA")

    username = read_config("local_user.name")
    # TODO: check after adding kerberos user that everything is also OK
    # TODO: clean kerberos info
    out = subp.run(
        ["bash", CLEANUP_CA, "--username", username])

    assert out.returncode == 0, "Something break in cleanup script :("
    env_logger.debug("Cleanup of local CA is completed")

cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(setup_krb_client)
cli.add_command(cleanup_ca)
cli.add_command(prepair)
cli.add_command(setup_krb_server)

if __name__ == "__main__":
    cli()
