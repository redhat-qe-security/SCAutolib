import click
from SCAutolib.src.env import *


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
@click.option("--ip", type=click.STRING,
              help="IP address of IPA server to setup with", required=False)
@click.option("--ca", is_flag=True, required=False,
              help="Flag for setting up the local CA")
@click.option("--install-missing", "-m", is_flag=True, required=False,
              help="Silently install missing packages, if it would be needed")
def prepare(cards, conf, ipa, ip, ca, install_missing):
    """
    Prepair the test environment including temporary directories, necessary
    configuration files and services. Also can automatically run setup for local
    CA, virtual smart card and installing IPA client with adding IPA users
    defined in configrutation file.
    """
    load_env(conf)
    if not check_config():
        env_logger.error("Configuration file miss required fields. Check logs for"
                         "more information.")
        exit(1)

    prep_tmp_dirs()
    env_logger.debug("Temporary directories are created")

    general_setup(install_missing)
    create_sssd_config()
    check_semodule()

    if ipa:
        env_logger.debug("Start setup of IPA client")
        if not ip:
            env_logger.debug("No IP address for IPA server is given.")
            env_logger.debug("Try to get IP address of IPA server from "
                             "configuration file.")
            ip = read_config("ipa_server_ip")
        if ip is None:
            env_logger.error("Can't find IP address of IPA server in "
                             "configuration file")
            exit(1)
        root_passwd = read_config("ipa_server_root")
        install_ipa_client_(ip, root_passwd)

    if ca:
        env_logger.debug("Start setup of local CA")
        prepare_dir(read_env("CA_DIR"))
        create_cnf('ca')
        setup_ca_(DOTENV)

    if cards:
        if ca:
            user = read_config("local_user")
            env_logger.debug(f"Start setup of virtual smart cards for local user {user}")
            create_sc(user)

        if ipa:
            user = read_config("ipa_user")
            add_ipa_user_(user)
            env_logger.debug(f"Start setup of virtual smart cards for IPA user {user}")
            create_sc(user)


@click.command()
@click.option("--conf", "-c", type=click.Path(), required=True,
              help="Path to YAML configuration file")
def setup_ca(conf):
    """
    CLI command for setup the local CA.
    """
    # TODO: generate certs for Kerberos
    env_path = load_env(conf)
    general_setup()
    prepare_dir(read_env("CA_DIR"))
    prep_tmp_dirs()
    create_cnf('ca')
    setup_ca_(env_path)


@click.command()
@click.option("-u", "--username", type=click.STRING)
@click.option("-c", "--conf", type=click.STRING, default=None)
@click.option("--key", "-k", help="Path to private key for the user.")
@click.option("--cert", "-C", help="Path to certificate for the user.")
@click.option("--card-dir", "-d", help="Path to card directory where virtual "
                                       "card to be created")
@click.option("--password", "-p", help="Password fot the user to be set")
@click.option("--local", "-l", is_flag=True,
              help="Flag if this user should be a local user (added to the system)")
def setup_virt_card(username, conf, key, cert, card_dir, password, local):
    """
    Setup virtual smart card. Has to be run after configuration of the local CA.
    """
    if conf is not None:
        load_env(conf)
    user = read_config(username)
    general_setup()
    if user is None:
        if not all([key, cert, username, card_dir, password, local]):
            raise
        env_logger.debug(f"User {username} is not in the configuration file. "
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
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML configuration file")
def cleanup_ca():
    """
    Cleanup the host after configuration of the testing environment.
    """
    env_logger.debug("Start cleanup of local CA")

    username = read_config("local_user.name")
    # TODO: check after adding kerberos user that everything is also OK
    # TODO: clean kerberos info
    out = run(
        ["bash", CLEANUP_CA, "--username", username])

    assert out.returncode == 0, "Something break in cleanup script :("
    env_logger.debug("Cleanup of local CA is completed")


@click.command()
@click.option("--ip", "-i")
def setup_ipa_server(ip):
    setup_ipa_server_()


@click.command()
@click.option("--conf", "-c", default='', help="Path to YAML configuration file")
@click.option("--ip", "-i", default='', help="IP address of IPA server.")
def install_ipa_client(ip, conf):
    if conf:
        load_env(conf)
    if not ip:
        ip = read_config("ipa_server_ip")
    if ip is None:
        msg = "No IP address for IPA server is provided. Can't continue..."
        env_logger.error(msg)
        raise click.MissingParameter(msg)
    root_passwd = read_config("ipa_server_root")
    install_ipa_client_(ip, root_passwd)


@click.command()
@click.option("--username", "-u", required=True,
              help="Username to be added to IPA server. If username is present in the"
                   "coniguration file, values from this object would be used")
@click.option("--user-dir", "-d", default=None,
              help="User directory to create on the system for placing cert and"
                   "private key from IPA server.")
def add_ipa_user(username, user_dir):
    user = read_config(username)
    if user is None:
        env_logger.debug(f"User {username} is not present in the configuration "
                         f"file. Creating a new one")
        if user_dir is None:
            env_logger.error("No user directory is specified. Exit")
            exit(1)
        user = dict()
        user["name"] = username
        user["card_dir"] = user_dir
    add_ipa_user_(user)
    create_sc(user)


cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(cleanup_ca)
cli.add_command(prepare)
cli.add_command(setup_ipa_server)
cli.add_command(install_ipa_client)
cli.add_command(add_ipa_user)


if __name__ == "__main__":
    cli()
