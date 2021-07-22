import click

from SCAutolib.src import load_env, CLEANUP_CA
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
def prepare(setup, conf, ipa):
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
    env_file = load_env(conf)

    prep_tmp_dirs()
    env_logger.debug("tmp directories are created")

    users = read_config("users")
    for user in users:
        username = user["name"]
        card_dir = user["card_dir"]
        prepare_dir(card_dir)

        if user["local"]:
            create_sssd_config(username)
            env_logger.debug("SSSD configuration file is updated")

            create_cnf(username, join(card_dir, "conf"))

        create_softhsm2_config(card_dir)
        env_logger.debug("SoftHSM2 configuration file is created in the "
                         f"{card_dir}/conf/softhsm2.conf")

        create_virt_card_service(username, card_dir)

    check_semodule()

    create_cnf("ca")

    if setup:
        setup_ca_(env_file)
        for user in users:
            setup_virt_card_(user)


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
    create_virt_card_service(username, card_dir)
    # setup_virt_card_()


@click.command()
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def cleanup_ca():
    """
    Cleanup the host after configuration of the testing environment.
    """
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
cli.add_command(cleanup_ca)
cli.add_command(prepare)


if __name__ == "__main__":
    cli()
