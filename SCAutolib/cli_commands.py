"""
Implementation of CLI commands for SCAutolib.
"""

import click

from SCAutolib.controller import Controller
from SCAutolib import logger
from SCAutolib import exceptions
from enum import Enum, auto


class ReturnCode(Enum):
    """
    Enum for return codes
    """
    SUCCESS = 0
    MISSING_CA = auto()
    FAILURE = auto()
    ERROR = auto()
    EXCEPTION = auto()
    UNKNOWN = auto()


@click.group()
@click.option("--conf", "-c",
              required=True,
              default="./conf.json",
              type=click.Path(exists=True, resolve_path=True),
              show_default=True,
              help="Path to JSON configuration file.")
@click.option('--force', "-f", is_flag=True, default=False, show_default=True,
              help="Force the command to overwrite configuration if it exists.")
@click.option("--verbose", "-v", default="INFO", show_default=True,
              type=click.Choice(
                  ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
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
    return ReturnCode.SUCCESS


@click.command()
@click.option("--gdm", "-g",
              required=False,
              default=False,
              is_flag=True,
              help="Install GDM package")
@click.option("--install-missing", "-i",
              required=False,
              default=False,
              is_flag=True,
              help="Install missing packages")
@click.pass_context
def prepare(ctx, gdm, install_missing):
    """Configure entire system for smart cards based on the config file."""
    ctx.obj["CONTROLLER"].prepare(ctx.obj["FORCE"], gdm, install_missing)
    return ReturnCode.SUCCESS


@click.command()
@click.argument("name", required=True, default=None)
@click.pass_context
def setup_user(ctx, name):
    """Configure user with smart cards (if set) based on the config file."""
    cnt = ctx.obj["CONTROLLER"]
    try:
        user_dict = cnt.get_user_dict(name)
        cnt.init_ca(user_dict["local"])
    except exceptions.SCAutolibMissingCA:
        logger.error(f"CA is not configured on the system")
        return ReturnCode.MISSING_CA
    except exceptions.SCAutolibException:
        logger.warning(f"User {name} not found in config file, "
                       f"trying to create a new one")
    user = cnt.setup_user(user_dict, ctx.obj["FORCE"])
    cnt.enroll_card(user, ctx.obj["FORCE"])
    return ReturnCode.SUCCESS


cli.add_command(setup_ca)
cli.add_command(prepare)
cli.add_command(setup_user)
