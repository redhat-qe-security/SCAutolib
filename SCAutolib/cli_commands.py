"""
Implementation of CLI commands for SCAutolib.

This module defines the command-line interface (CLI) for the ``scauto``
tool, utilizing the ``click`` library. It provides a
user-friendly interface for system preparation, CA configuration, user setup
with smart cards, and cleanup operations. Additionally,
it includes a specialized command group for automated GUI testing.
"""


import click
from pathlib import Path
from sys import exit

from collections import OrderedDict

from SCAutolib import logger, exceptions, schema_user
from SCAutolib.controller import Controller
from SCAutolib.enums import ReturnCode


def check_conf_path(conf):
    """
    Validates and resolves the path to the JSON configuration file.

    :param conf: The path string to the configuration file.
    :type conf: str
    :return: A resolved ``Path`` object if the file exists.
    :rtype: pathlib.Path
    :raises click.BadParameter: If the path does not exist.
    """
    return click.Path(exists=True, resolve_path=True)(conf)


# In Help output, force the subcommand list to match the order
# listed in this file.   Solution was found here:
# https://github.com/pallets/click/issues/513#issuecomment-301046782
class NaturalOrderGroup(click.Group):
    """
    A custom ``click.Group`` subclass that ensures subcommands are listed in the
    help output in the order they were defined in the code.
    This overrides ``click``'s default alphabetical sorting for subcommands.
    """
    def __init__(self, name=None, commands=None, **attrs):
        """
        Initializes the NaturalOrderGroup, ensuring the commands dictionary
        is an ``OrderedDict`` to maintain insertion order.

        :param name: The name of the command group.
        :type name: str, optional
        :param commands: A dictionary of commands belonging to this group.
        :type commands: OrderedDict or dict, optional
        :param attrs: Additional attributes for the ``click.Group``.
        :type attrs: dict
        """
        if commands is None:
            commands = OrderedDict()
        elif not isinstance(commands, OrderedDict):
            commands = OrderedDict(commands)
        click.Group.__init__(self, name=name,
                             commands=commands,
                             **attrs)

    def list_commands(self, ctx):
        """
        Lists the command names in their defined order.

        :param ctx: The Click context object.
        :type ctx: click.Context
        :return: A list of command names in their defined order.
        :rtype: list
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
              help="Set the verbosity level of the output.")
@click.pass_context
def cli(ctx, force, verbose, conf):
    """
    The main entry point for the SCAutolib CLI.
    It initializes global settings and the Controller instance based on
    the configuration.

    :param ctx: The Click context object, used to pass data to subcommands.
    :type ctx: click.Context
    :param force: A flag indicating whether operations should force overwrites
                  of existing configurations or files.
    :type force: bool
    :param verbose: The logging verbosity level for the entire CLI execution.
    :type verbose: str (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``, or
                   ``CRITICAL``)
    :param conf: The path to the JSON configuration file used by the library.
    :type conf: str
    :return: None
    """
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
    """
    Configures the entire system for smart card operations and testing
    based on the configuration file. This includes
    installing packages and setting up CAs, users, and smart cards.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param gdm: If ``True``, the GNOME Display Manager (GDM) package will be
                installed.
    :type gdm: bool
    :param install_missing: If ``True``, instructs the command to automatically
                            install any prerequisite packages detected as
                            missing on the system.
    :type install_missing: bool
    :param graphical: If ``True``, ensures that all dependencies specifically
                      required for the GUI testing module are installed.
    :type graphical: bool
    :return: The command exits with a success code upon completion.
    :rtype: No return (exits the process).
    """
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
    Configures Certificate Authorities (CAs) on the system from the
    configuration file. Can target 'all', 'local',
    or 'ipa' CAs.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param ca_type: Specifies the type of CA to configure. If 'all', both local
                    and IPA CAs from the configuration will be set up.
    :type ca_type: str
    :return: The command exits with a success code upon completion.
    :rtype: No return (exits the process).
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
    """
    Configures a user, optionally with smart card integration, from config
    or CLI arguments. Handles CA initialization and user/card setup.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param name: The username for the user to be configured or created.
    :type name: str
    :param card_dir: The file system path where the smart card's related files
                     will be stored. Required if creating a new user via CLI
                     without a config entry.
    :type card_dir: str or None
    :param card_type: The type of smart card to associate with the user.
                      Options include ``virtual``, ``real`` (physical), or
                      ``removinator``.
    :type card_type: str
    :param passwd: The password for the user. Required if creating a new user
                   via CLI without a config entry.
    :type passwd: str or None
    :param pin: The PIN for the smart card associated with the user. Required
                if creating a new user via CLI without a config entry.
    :type pin: str or None
    :param user_type: The type of user account to create: ``local`` system user
                      or an ``ipa`` (Identity Management for Linux) user.
    :type user_type: str
    :return: The command exits with a success code or an error code upon
             failure.
    :rtype: No return (exits the process).
    """
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
    Cleans up all configurations and system changes made by SCAutolib commands,
    particularly from ``prepare``. Restores the system to a clean state (as
    much as possible).

    :param ctx: The Click context object, containing the ``CONTROLLER`` instance.
    :type ctx: click.Context
    :return: The command exits with a success code upon completion.
    :rtype: No return (exits the process).
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
    """
    Command group for running chained GUI test commands.
    Manages graphical environment dependencies.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param install_missing: If ``True``, ensures that all necessary packages for
                            GUI testing are installed.
    :type install_missing: bool
    :return: None
    """
    pass


@gui.command()
def init():
    """
    Initializes the GUI environment for automated testing.
    Restarts the display manager for a clean state.

    :return: A string literal ``"init"`` that signals the execution of the
             GUI initialization action within the ``run_all`` callback.
    :rtype: str
    """
    return "init"


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
@click.argument("name")
def assert_text(name, no):
    """
    Asserts the presence or absence of a specific text string on the
    currently displayed GUI screen.

    :param name: The text string to search for on the screen.
    :type name: str
    :param no: If ``True``, this reverses the assertion, checking that the text
               is *not* found on the screen.
    :type no: bool
    :return: A string representing the assertion action to be performed by the
             ``run_all`` callback (e.g., ``"assert_text:ExpectedText"`` or
             ``"assert_no_text:UnexpectedText"``).
    :rtype: str
    """
    if no:
        return f"assert_no_text:{name}"
    return f"assert_text:{name}"


@gui.command()
@click.argument("name")
def click_on(name):
    """
    Simulates a mouse click action on a GUI object or area that contains the
    specified text.

    :param name: The string text content of the GUI object that should be
                 clicked.
    :type name: str
    :return: A string representing the click action to be performed by the
             ``run_all`` callback (e.g., ``"click_on:ButtonLabel"``).
    :rtype: str
    """
    return f"click_on:{name}"


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
def check_home_screen(no):
    """
    Verifies if the currently displayed graphical screen is (or is not) the
    expected "home screen" environment. Currently the Gnome Shell home screen
    from RHEL, CentOS and Fedora is detected.

    :param no: If ``True``, reverses the check to verify that the current screen
               is *not* the home screen.
    :type no: bool
    :return: A string representing the home screen check action to be performed
             by the ``run_all`` callback (e.g., `"check_home_screen"` or
             `"check_no_home_screen"`).
    :rtype: str
    """
    if no:
        return "check_no_home_screen"
    return "check_home_screen"


@gui.command()
@click.argument("keys")
def kb_send(keys):
    """
    Sends one or more specific key press events to the active GUI window.

    :param keys: A string representing the key or sequence of keys to simulate
                 pressing (e.g., ``enter``, ``alt+f4``).
    :type keys: str
    :return: A string representing the keyboard send action to be performed by
             the ``run_all`` callback (e.g., `"kb_send:enter"`).
    :rtype: str
    """
    return f"kb_send:{keys}"


@gui.command()
@click.argument("keys")
def kb_write(keys):
    """
    Simulates typing a literal string of characters into the active GUI input
    field or window. After the string is sent, an 'enter' key press is
    automatically appended.

    :param keys: The string of text to be written or typed into the GUI.
    :type keys: str
    :return: A string representing the keyboard write action to be performed by
             the ``run_all`` callback (e.g., `"kb_write:myusername"`).
    :rtype: str
    """
    return f"kb_write:{keys}"


@gui.command()
def done():
    """
    Serves as a finalization step for a sequence of GUI test commands.
    It triggers cleanup actions after all preceding GUI test operations have
    completed.

    :return: A string literal `"done"` that signals the execution of the
             GUI cleanup action within the ``run_all`` callback.
    :rtype: str
    """
    return "done"


@gui.result_callback()
@click.pass_context
def run_all(ctx, actions, install_missing):
    """
    Executes all chained GUI test actions in the order they were provided on
    the command line. It initializes the graphical
    environment and performs specified GUI automation steps.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param actions: A list of strings, where each string is a representation
                    of a GUI test action to be performed (e.g., `"init"`,
                    `"assert_text:ExpectedText"`).
    :type actions: list of str
    :param install_missing: A boolean flag indicating whether any missing
                            packages required for the graphical setup should be
                            installed prior to running the GUI actions.
    :type install_missing: bool
    :return: This function does not explicitly return a value. It executes
             the GUI test workflow.
    :rtype: None
    """
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
