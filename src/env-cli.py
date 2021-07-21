import click
import paramiko
from time import sleep
from pysftp import CnOpts


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
@click.option("--ipa", "-i", help="Setup IPA client with existed IPA server (IP address in conf file)")
def prepare(setup, conf):
    """
    Prepair the whole test environment including temporary directories, necessary
    configuration files and services. Also can automatically run setup for local
    CA and virtual smart card.

    Args:
        krb: if you want to deploy kerberos server and client
        setup: if you want to automatically run other setup steps
        conf: path to configuration file im YAML format
        work_dir: path to working directory. Can be overwritten
                  by variable CA_DIR in confugration file
        env_file: path to already existing .env file
    """
    # TODO: add getting of work_dir from configuration file
    env_file = load_env(conf)

    prep_tmp_dirs()
    env_logger.debug("tmp directories are created")

    username, card_dir = read_config("local_user.name", "local_user.card_dir")
    create_sssd_config(username)
    env_logger.debug("SSSD configuration file is updated")
    card_dir = read_config("local_user.card_dir")
    create_softhsm2_config(card_dir)
    env_logger.debug("SoftHSM2 configuration file is created in the "
                     f"{CONF_DIR}/softhsm2.conf")

    username = read_config("local_user.name")
    create_virt_card_config(username, card_dir)
    env_logger.debug("Configuration files for virtual smart card are created.")

    check_semodule()

    create_cnf(username, card_dir)

    if setup:
        setup_ca_(conf, env_file)
        setup_virt_card_("local_user")


@click.command()
@click.option("--conf", "-c", type=click.Path(), required=True,
              help="Path to YAML file with configurations")
def setup_ca(conf):
    """
    CLI command for setup the local CA.

    Args:
        conf: Path to YAML file with configurations
        work_dir: Path to working directory. By default working directory is
                  in the source directory of the library
        env_file: Path to .env file with specified variables
    """
    # TODO: generate certs for Kerberos
    env_path = load_env(conf)
    mkdir(config("CA_DIR"))
    mkdir(config("CONF_DIR"))
    create_cnf('ca')
    # prepare_ca_configs()
    # prepare_general_configs()

    setup_ca_(conf, env_path)


@click.command()
@click.option("-u", "--user", type=click.STRING, required=True)
def setup_virt_card(user):
    """
    Setup virtual smart card. Has to be run after configuration of the local CA.

    Args:
        work_dir: Working directory where all necessary files and directories
                  are/will be stored
    """
    # env_path = load_env(env, work_dir)
    username, card_dir = read_config(f'{user}.name', f'{user}.card_dir')
    create_softhsm2_config(card_dir)
    create_virt_card_config(username, card_dir)
    # setup_virt_card_()


@click.command()
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
def setup_krb_server(new):
    check_env()

    cert, key = generate_krb_certs()
    env_logger.debug(f"KDC certificat: {cert}")
    env_logger.debug(f"KDC private key: {key}")
    krb_ip, krb_root_passwd, krb_srv_name = read_config(
        "krb.ip", "krb.root_passwd", "krb.server_name")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(krb_ip, 22, "root", krb_root_passwd)
    env_logger.debug(f"SSH connectin to {krb_ip} is istablished")
    if new:
        # Install required packages on fresh machine
        pkgs = ["ccid", "opensc", "esc", "pcsc-lite", "pcsc-lite-libs", "gdm",
                "nss-pam-ldapd", "krb5-workstation", "krb5-libs", "krb5-pkinit",
                "krb5-server", "krb5-pkinit-openssl", "nss-tools", "python3-ldap"]
        ssh.exec_command(f"dnf install -y {' '.join(pkgs)}")

        # Change host name from configuration file
        _, stdout, _ = ssh.exec_command("hostname")
        if krb_srv_name not in stdout:
            ssh.exec_command(f"hostnamectl set-hostaname {krb_srv_name}")

    # Need for strcit host key cheking disabled
    cnopts = CnOpts()
    cnopts.hostkeys = None
    with Connection(krb_ip, "root", password=krb_root_passwd, cnopts=cnopts) as sftp:
        env_logger.debug(f"SFTP with server {krb_ip} connection established")
        paths = ({"original": "/var/kerberos/krb5kdc/kdc.pem", "new": cert},
                 {"original": "/var/kerberos/krb5kdc/kdckey.pem", "new": key},
                 {"original": "/var/kerberos/krb5kdc/kdc-ca.pem", "new": f"{CA_DIR}/rootCA.crt"})
        for item in paths:
            if sftp.exists(item["original"]):
                name = split(item["original"])[1].replace(".", "-original.")
                sftp.get(item["original"], f"{BACKUP}/{name}")
                env_logger.debug(f"File {item['original']} from Kerberos server "
                                 f"({krb_ip}) is stored to {BACKUP}/{name}")
            sftp.put(item["new"], item["original"])
            env_logger.debug(f"File {item['new']} from localhost is copied to "
                             f"Kerberos server ({krb_ip}) to {item['original']}")

        create_kdc_config(sftp)
        create_krb_config(sftp)

    ssh.exec_command("systemctl restart krb5kdc")
    ssh.close()
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
cli.add_command(prepare)
cli.add_command(setup_krb_server)

if __name__ == "__main__":
    cli()
