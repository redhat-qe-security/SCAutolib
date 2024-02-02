"""
Implementation of CLI commands for SCAutolib.
"""

import click
from pathlib import Path
from sys import exit

from SCAutolib import logger, exceptions, schema_user
from SCAutolib.controller import Controller
from SCAutolib.enums import ReturnCode


@click.group()
@click.option("--conf", "-c",
              default="./conf.json",
              type=click.Path(exists=True, resolve_path=True),
              show_default=True,
              help="Path to JSON configuration file.")
@click.option('--force', "-f", is_flag=True, default=False, show_default=True,
              help="Force the command to overwrite configuration if it exists.")
@click.option("--verbose", "-v", default="DEBUG", show_default=True,
              type=click.Choice(
                  ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                  case_sensitive=False),
              help="Verbosity level.")
@click.pass_context
def cli(ctx, force, verbose, conf):
    logger.setLevel(verbose)
    ctx.ensure_object(dict)  # Create a dict to store the context
    ctx.obj["FORCE"] = force  # Store the force option in the context
    ctx.obj["CONTROLLER"] = Controller(conf)


@click.command()
@click.option("--ca-type", "-t",
              required=False,
              default='all',
              type=click.Choice(['all', 'local', 'ipa'], case_sensitive=False),
              show_default=True,
              help="Type of the CA to be configured. If not set, all CA's "
                   "from the config file would be configured")
@click.pass_context
def setup_ca(ctx, ca_type):
    """
    Configure the CA's in the config file. If more than one CA is
    specified, specified CA type would be configured.
    """
    cnt = ctx.obj["CONTROLLER"]
    if ca_type == 'all':
        cnt.setup_local_ca(force=ctx.obj["FORCE"])
        cnt.setup_ipa_client(force=ctx.obj["FORCE"])
    elif ca_type == 'local':
        cnt.setup_local_ca(force=ctx.obj["FORCE"])
    elif ca_type == 'ipa':
        cnt.setup_ipa_client(force=ctx.obj["FORCE"])
    exit(ReturnCode.SUCCESS.value)


@click.command()
@click.option("--gdm", "-g",
              required=False,
              default=False,
              is_flag=True,
              help="Install GDM package")
@click.option("--graphical",
              required=False,
              default=False,
              is_flag=True,
              help="Install dependencies for GUI testing module")
@click.option("--install-missing", "-i",
              required=False,
              default=False,
              is_flag=True,
              help="Install missing packages")
@click.pass_context
def prepare(ctx, gdm, install_missing, graphical):
    """Configure entire system for smart cards based on the config file."""
    ctx.obj["CONTROLLER"].prepare(
        ctx.obj["FORCE"],
        gdm,
        install_missing,
        graphical
    )
    exit(ReturnCode.SUCCESS.value)


@click.command()
@click.argument("name",
                required=True,
                default=None)
@click.option("--card-dir", "-d",
              required=False,
              default=None,
              help="Path to the directory where smart card should be created")
@click.option("--card-type", "-t",
              required=False,
              default="virtual",
              type=click.Choice(
                  ["virtual", "real", "removinator"], case_sensitive=False),
              show_default=True,
              help="Type of the smart card to be created")
@click.option("--passwd", "-p",
              required=False,
              default=None,
              show_default=True,
              help="Password for the user")
@click.option("--pin", "-P",
              required=False,
              default=None,
              show_default=True,
              help="PIN for the smart card")
@click.option("--user-type", "-T",
              required=False,
              default="local",
              type=click.Choice(["local", "ipa"], case_sensitive=False),
              show_default=True,
              help="Type of the user to be created")
@click.pass_context
def setup_user(ctx, name, card_dir, card_type, passwd, pin, user_type):
    """Configure user with smart cards (if set) based on the config file."""
    cnt = ctx.obj["CONTROLLER"]
    logger.info(f"Start setup user {name}")
    try:
        user_dict = cnt.get_user_dict(name)
    except exceptions.SCAutolibMissingUserConfig:
        logger.warning(f"User {name} not found in config file, "
                       f"trying to create a new one")
        if not all([card_dir, card_type, passwd, pin, user_type]):
            logger.error("Not all required arguments are set")
            logger.error("Required arguments: --card-dir, --pin, --password")
            exit(ReturnCode.ERROR.value)
        user_dict = schema_user.validate(
            {"name": name,
             "card_dir": Path(card_dir),
             "card_type": card_type,
             "passwd": passwd,
             "pin": pin,
             "local": user_type == "local"})
        logger.debug(f"User dict: {user_dict}")

    try:
        cnt.init_ca(user_dict["local"])
    except exceptions.SCAutolibMissingCA:
        logger.error("CA is not configured on the system")
        exit(ReturnCode.MISSING_CA.value)

    try:
        user = cnt.setup_user(user_dict, ctx.obj["FORCE"])
        cnt.enroll_card(user, ctx.obj["FORCE"])
    except exceptions.SCAutolibException:
        logger.error("Something went wrong")
        exit(ReturnCode.FAILURE.value)
    exit(ReturnCode.SUCCESS.value)


@click.command()
@click.pass_context
def cleanup(ctx):
    """
    Cleanup all the configurations and system changes done by the prepare
    command.
    """
    ctx.obj["CONTROLLER"].cleanup()
    exit(ReturnCode.SUCCESS.value)


cli.add_command(setup_ca)
cli.add_command(prepare)
cli.add_command(setup_user)
cli.add_command(cleanup)
