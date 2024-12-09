"""
Implementation of CLI commands for SCAutolib.
"""

import click
from pathlib import Path
from sys import exit

from collections import OrderedDict

from SCAutolib import logger, exceptions, schema_user
from SCAutolib.controller import Controller
from SCAutolib.enums import ReturnCode


def check_conf_path(conf):
    return click.Path(exists=True, resolve_path=True)(conf)


# In Help output, force the subcommand list to match the order
# listed in this file.   Solution was found here:
# https://github.com/pallets/click/issues/513#issuecomment-301046782
class NaturalOrderGroup(click.Group):
    """
    Command group trying to list subcommands in the order they were added.
    Example use::

    @click.group(cls=NaturalOrderGroup)

    If passing dict of commands from other sources, ensure they are of type
    OrderedDict and properly ordered, otherwise order of them will be random
    and newly added will come to the end.
    """
    def __init__(self, name=None, commands=None, **attrs):
        if commands is None:
            commands = OrderedDict()
        elif not isinstance(commands, OrderedDict):
            commands = OrderedDict(commands)
        click.Group.__init__(self, name=name,
                             commands=commands,
                             **attrs)

    def list_commands(self, ctx):
        """
        List command names as they are in commands dict.

        If the dict is OrderedDict, it will preserve the order commands
        were added.
        """
        return self.commands.keys()


@click.group(cls=NaturalOrderGroup)
@click.option("--conf", "-c",
              default="./conf.json",
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
    parsed_conf = None
    if ctx.invoked_subcommand != "gui":
        parsed_conf = check_conf_path(conf)
    ctx.obj["CONTROLLER"] = Controller(parsed_conf)


@cli.command()
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


@cli.command()
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


@cli.command()
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


@cli.command()
@click.pass_context
def cleanup(ctx):
    """
    Cleanup all the configurations and system changes done by the prepare
    command.
    """
    ctx.obj["CONTROLLER"].cleanup()
    exit(ReturnCode.SUCCESS.value)


@cli.group(cls=NaturalOrderGroup, chain=True)
@click.option("--install-missing", "-i",
              required=False,
              default=False,
              is_flag=True,
              help="Install missing packages")
@click.pass_context
def gui(ctx, install_missing):
    """ Run GUI Test commands """
    pass


@gui.command()
def init():
    """ Initialize GUI for testing """
    return "init"


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
@click.argument("name")
def assert_text(name, no):
    """ Check if a word is found on the screen """
    if no:
        return f"assert_no_text:{name}"
    return f"assert_text:{name}"


@gui.command()
@click.argument("name")
def click_on(name):
    """ Click on object containing word """
    return f"click_on:{name}"


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
def check_home_screen(no):
    """ Check if screen appears to be the home screen """
    if no:
        return "check_no_home_screen"
    return "check_home_screen"


@gui.command()
@click.argument("keys")
def kb_send(keys):
    """ Send key(s) to keyboard """
    return f"kb_send:{keys}"


@gui.command()
@click.argument("keys")
def kb_write(keys):
    """ Send string to keyboard """
    return f"kb_write:{keys}"


@gui.command()
def done():
    """ cleanup after testing """
    return "done"


@gui.result_callback()
@click.pass_context
def run_all(ctx, actions, install_missing):
    """ Run all cli actions in order """
    ctx.obj["CONTROLLER"].setup_graphical(install_missing, True)

    from SCAutolib.models.gui import GUI
    gui = GUI(from_cli=True)
    for action in actions:
        if "init" in action:
            gui.__enter__()
        if "assert_text" in action:
            assert_text = action.split(":", 1)[1]
            gui.assert_text(assert_text)
        if "assert_no_text" in action:
            assert_text = action.split(":", 1)[1]
            gui.assert_no_text(assert_text)
        if "click_on" in action:
            click_on = action.split(":", 1)[1]
            gui.click_on(click_on)
        if "check_home_screen" in action:
            gui.check_home_screen()
        if "check_no_home_screen" in action:
            gui.check_home_screen(False)
        if "kb_send" in action:
            params = action.split(":", 1)[1].split()[0]
            gui.kb_send(params)
        if "kb_write" in action:
            params = action.split(":", 1)[1].split()[0]
            gui.kb_write(params)
            gui.kb_send('enter')
        if "done" in action:
            gui.__exit__(None, None, None)
            ctx.obj["CONTROLLER"].cleanup()


if __name__ == "__main__":
    cli()
