import click
from SCAutolib import init_config
from SCAutolib.env import *


@click.group()
def cli():
    pass


@click.command()
@click.option("--cards", "-C", is_flag=True, default=False, required=False,
              help="Flag for setting up virtual smart cards for local_user "
                   "and ipa_user from the configuration file")
@click.option("--conf", "-c", type=click.Path(),
              help="Path to YAML configuration file.", required=False)
@click.option("--ipa", "-i", is_flag=True,
              help="Setup IPA client with existed IPA server (IP address in "
                   "conf file or specify by --ip parameter)")
@click.option("--server-ip", type=click.STRING,
              help="IP address of IPA server to setup with", required=False)
@click.option("--server-hostname", type=click.STRING, required=False,
              default=None,
              help="Hostname of IPA server. This name would be added to "
                   "/etc/hosts")
@click.option("--ca", is_flag=True, required=False,
              help="Flag for setting up the local CA")
@click.option("--install-missing", "-m", is_flag=True, required=False,
              default=False,
              help="Silently install missing packages, if it would be needed")
@click.option("--no-gdm", is_flag=True, default=False, required=False,
              help="Specifies if GDM package should not be installed. "
                   "Will speedup the setup phase")
def prepare(cards, conf, ipa, server_ip, ca, install_missing, server_hostname,
            no_gdm):
    """
    Prepare the test environment including temporary directories, necessary
    configuration files and services. Also can automatically run setup for local
    CA, virtual smart card and installing IPA client with adding IPA users
    defined in configuration file.
    """
    logger.info("Start setting up system for smart card testing")
    if not check_config(conf):
        logger.error("Configuration file miss required fields. Check logs "
                     "for more information.")
        exit(1)

    logger.info("Preparing necessary directories")
    prepare_dirs()
    logger.info("Directories are created")
    init_config(conf)
    logger.info("Initialisation of library configuration files is "
                "completed.")
    logger.info("Start general setup")
    try:
        general_setup(install_missing, no_gdm)
    except Exception as e:
        logger.error(e)
        exit(1)

    create_sssd_config()

    if ipa:
        try:
            logger.info("Start setup of IPA client")
            if not server_ip:
                logger.debug("No IP address for IPA server is given.")
                logger.debug("Try to get IP address of IPA server from "
                             "configuration file.")
                server_ip = read_config("ipa_server_ip")
                if not server_ip:
                    logger.error("Can't find IP address of IPA server in "
                                 "configuration file")
                    exit(1)
            else:
                set_config("ipa_server_ip", server_ip)
            server_root_passwd = read_config("ipa_server_root")
            install_ipa_client_(server_ip, server_root_passwd, server_hostname)
            logger.info("IPA client is installed on the system")
        except:
            logger.error(format_exc())
            logger.error("IPA client installation is failed.")
            run("ipa-client-install --uninstall -U")
            exit(1)

    if ca:
        logger.info("Start setup of local CA")
        create_dir(LIB_CA)
        setup_ca_()

    if cards:
        if ca:
            user = read_config("local_user")
            logger.info(
                f"Start setup of virtual smart cards for local user {user}")
            create_sc(user)
            logger.info(f"Setup of virtual smart card for user {user} "
                        f"is completed")
        if ipa:
            user = read_config("ipa_user")
            add_ipa_user_(user, server_hostname)
            logger.info(
                f"Start setup of virtual smart cards for IPA user {user}")
            create_sc(user)
            logger.info(f"Setup of virtual smart card for user {user} "
                        f"is completed")
    logger.info("Preparation of the environments is completed")
    exit(0)


@click.command()
@click.option("--conf", "-c", type=click.Path(), required=True,
              help="Path to YAML configuration file")
def setup_ca(conf):
    """
    CLI command for setup the local CA.
    """
    # TODO: generate certs for Kerberos
    init_config(conf)
    general_setup()
    prepare_dirs()
    create_cnf('ca')
    setup_ca_()


@click.command()
@click.option("-u", "--username", type=click.STRING)
@click.option("-c", "--conf", type=click.File(lazy=True), default=None)
@click.option("--key", "-k", help="Path to private key for the user.")
@click.option("--cert", "-C", help="Path to certificate for the user.")
@click.option("--card-dir", "-d", help="Path to card directory where virtual "
                                       "card to be created")
@click.option("--password", "-p", help="Password fot the user to be set")
@click.option("--local", "-l", is_flag=True,
              help="True if a user for virtual smart card is a local user "
                   "(would be added to the system). False if a user is "
                   "IPA user (has to already exist on IPA server)")
def setup_virt_card(username, key, cert, card_dir, password, local):
    """
    Setup virtual smart card. Has to be run after configuration of the local CA.
    """
    if not read_config("ready"):
        logger.error(
            "Please, run prepare command with configuration file.")
        exit(1)

    user = read_config(username)
    general_setup()
    if user is None:
        if not all([key, cert, username, card_dir, password, local]):
            logger.error("Not all required parameters are set for adding "
                         f"virtual smart card to user {username}. "
                         f"Add all parameters via configuration file or via"
                         f"CLI parameters.")
            exit(1)
        logger.debug(f"User {username} is not in the configuration file. "
                     f"Using values from parameters")
        user = dict()
        user["name"] = username
        user["key"] = key
        user["cert"] = cert
        user["card_dir"] = card_dir
        user["passwd"] = password
        user["local"] = local

    create_sc(user)


@click.command()
def cleanup():
    """
    Cleanup the host after configuration of the testing environment. Delete
    created directories/files, or restore if directory/file already existed.
    """
    logger.debug("Start cleanup")

    try:
        cleanup_()
    except:
        logger.error("Cleanup is failed. Check logs for more info")
        logger.error(format_exc())
        exit(1)

    logger.debug("Cleanup is completed")
    exit(0)


@click.command()
@click.option("--ip", "-i")
def setup_ipa_server(ip):
    setup_ipa_server_()


@click.command()
@click.option("--ip", "-i", default='', help="IP address of IPA server.")
def install_ipa_client(ip):
    if not ip:
        ip = read_config("ipa_server_ip")
    if ip is None:
        msg = "No IP address for IPA server is provided. Can't continue..."
        logger.error(msg)
        exit(1)
    root_passwd = read_config("ipa_server_root")
    install_ipa_client_(ip, root_passwd)


@click.command()
@click.option("--username", "-u", required=True,
              help="Username to be added to IPA server. If username is present "
                   "in the configuration file, values from this object would "
                   "be used")
@click.option("--user-dir", "-d", default=None,
              help="User directory to create on the system for placing cert and"
                   "private key from IPA server.")
def add_ipa_user(username, user_dir):
    user = read_config(username)
    if user is None:
        logger.debug(f"User {username} is not present in the configuration "
                     f"file. Creating a new one")
        if user_dir is None:
            logger.error("No user directory is specified. Exit")
            exit(1)
        user = dict()
        user["name"] = username
        user["card_dir"] = user_dir
    add_ipa_user_(user)
    create_sc(user)


cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(cleanup)
cli.add_command(prepare)
cli.add_command(setup_ipa_server)
cli.add_command(install_ipa_client)
cli.add_command(add_ipa_user)

if __name__ == "__main__":
    cli()
