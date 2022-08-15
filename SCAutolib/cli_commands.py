"""
Implementation of CLI commands for SCAutolib.
"""

import click

from SCAutolib.controller import Controller
from SCAutolib import logger


@click.group()
@click.option('--force', "-f", is_flag=True, default=False, show_default=True,
              help="Force the command to overwrite configuration if it exists.")
@click.option("--verbose", "-v", default="INFO", show_default=True,
              type=click.Choice(
                  ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
              help="Increase verbosity. Max level is 3.")
@click.pass_context
def cli(ctx, force, verbose):
    logger.setLevel(verbose)
    ctx.ensure_object(dict)  # Create a dict to store the context
    ctx.obj["FORCE"] = force  # Store the force option in the context


@click.command()
@click.option("--ca-type", "-t",
              required=False,
              default='all',
              type=click.Choice(['all', 'local', 'ipa'], case_sensitive=False),
              show_default=True,
              help="Type of the CA to be configured. If not set, all CA's "
                   "from the config file would be configured")
@click.option("--conf-file", "-c",
              required=False,
              default="./conf.json",
              type=click.Path(exists=True, resolve_path=True),
              show_default=True)
@click.pass_context  # to pass context (ctx) parameter to the function
def setup_ca(ctx, conf_file, ca_type):
    """
    Configure the CA's in the config file. If more than one CA is
    specified, specified CA type would be configured.
    """
    cnt = Controller(conf_file)
    if ca_type == 'all':
        cnt.setup_local_ca(force=ctx.obj["FORCE"])
        cnt.setup_ipa_client(force=ctx.obj["FORCE"])
    elif ca_type == 'local':
        cnt.setup_local_ca(force=ctx.obj["FORCE"])
    elif ca_type == 'ipa':
        cnt.setup_ipa_client(force=ctx.obj["FORCE"])


@click.command()
@click.option("--conf", "-c", required=True)
@click.option("--force", "-f", required=False, default=False, is_flag=True)
@click.option("--gdm", "-g", required=False, default=False, is_flag=True)
@click.option("--install-missing", "-i", required=False, default=False,
              is_flag=True)
def prepare(conf, force, gdm, install_missing):
    """Configure entire system for smart cards based on the config file."""
    cnt = Controller(conf)
    cnt.prepare(force, gdm, install_missing)


@click.command()
@click.option("--conf", "-c", required=True)
@click.option("--force", "-f", required=False, default=False, is_flag=True)
@click.option("--name", "-n", required=True, default=None)
def setup_user(name, conf, force):
    cnt = Controller(conf)
    user_dict = cnt.get_user_dict(name)
    cnt.init_ca(user_dict["local"])
    user = cnt.setup_user(user_dict, force)
    cnt.enroll_card(user, force)


cli.add_command(setup_ca)
cli.add_command(prepare)
cli.add_command(setup_user)
