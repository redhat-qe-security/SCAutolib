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
from sys import exit, argv

from collections import OrderedDict

from SCAutolib import logger
from SCAutolib.controller import Controller
from SCAutolib.models.card import Card
from SCAutolib.enums import ReturnCode
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.utils import dump_to_json


def check_conf_path(conf: str):
    """
    Validates and resolves the path to the JSON configuration file.

    :param conf: The path string to the configuration file.
    :type conf: str
    :return: A resolved ``Path`` object if the file exists.
    :rtype: pathlib.Path
    :raises SCAutolibException: If there is a problem with the file.
    """
    try:
        return click.Path(exists=True, resolve_path=True)(conf)
    except click.BadParameter as e:
        raise SCAutolibException(str(e))


# In Help output, force the subcommand list to match the order
# listed in this file.   Solution was found here:
# https://github.com/pallets/click/issues/513#issuecomment-301046782
class NaturalOrderGroup(click.Group):
    """
    A custom ``click.Group`` subclass that ensures subcommands are listed in the
    help output in the order they were defined in the code.
    This overrides ``click``'s default alphabetical sorting for subcommands.
    """
    def __init__(self, name: str = None, commands: dict = None, **attrs):
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

    def list_commands(self, ctx: click.Context):
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
@click.option("--verbose", "-v", default="INFO", show_default=True,
              type=click.Choice(
                  ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                  case_sensitive=False),
              help="Set the verbosity level of the output.")
@click.pass_context
def cli(ctx: click.Context, force: bool, verbose: bool, conf: Path):
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
    logger.debug(f"Invocked CLI command: {' '.join(argv)}")
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
def prepare(ctx: click.Context, gdm: bool, install_missing: bool,
            graphical: bool):
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
@click.option("--prepare", "-P",
              required=False,
              default=False,
              is_flag=True,
              help="Prepare system for a card, including installing CA.")
@click.option("--insert", "-I",
              required=False,
              default=False,
              is_flag=True,
              help="Inserts a card to the system.")
@click.option("--remove", "-R",
              required=False,
              default=False,
              is_flag=True,
              help="Remove a card from the system.")
@click.option("--restore", "-C",
              required=False,
              default=False,
              is_flag=True,
              help="Restore system from the prepare step.")
@click.argument("card_name")
@click.pass_context
def card(ctx: click.Context, card_name: str, prepare: bool, insert: bool,
         remove: bool, restore: bool):
    """
    This function depending on the function that was given will prepare the
    system for a card, insert a card, remove a card or restore the system.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param card_name: The name of the card the transaction will run against.
    :type card_name: str
    :param prepare: If ``True``, system will be set-up with a card CA.
    :type prepare: bool
    :param insert: If ``True``, card will be inserted on the system.
    :type insert: bool
    :param remove: If ``True``, card will be removed from the system.
    :type remove: bool
    :param restore: If ``True``, system will be restored.
    :type restore: bool
    :return: The command exits with a success code upon completion.
    :rtype: No return (exits the process).
    """
    if not any([prepare, insert, remove, restore]):
        logger.error(
            "Some action (prepare, insert, remove or restore) is needed!")
        exit(ReturnCode.FAILURE.value)

    card = Card.load(card_name=card_name)
    if prepare:
        card.__enter__()
    if insert:
        card.insert()
    if remove:
        card.remove()
    if restore:
        card.restore_card_ca()
        card.__exit__(None, None, None)

    dump_to_json(card)
    exit(ReturnCode.SUCCESS.value)


@cli.command()
@click.pass_context
def cleanup(ctx: click.Context):
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
@click.option("--wait-time",
              required=False,
              default=5,
              help="Time to wait after running function before continuing")
@click.option("--no-screenshot",
              required=False,
              default=False,
              is_flag=True,
              help="Skip screenshots before and after gui functions")
@click.option("--no-check-difference",
              required=False,
              default=False,
              is_flag=True,
              help="Skip check difference after gui functions")
@click.pass_context
def gui(ctx: click.Context, install_missing: bool, wait_time: float,
        no_screenshot: bool, no_check_difference: bool):
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
             GUI initialization action within the ``gui_run_all`` callback.
    :rtype: str
    """
    return ("init",)


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
@click.option("--case-insensitive",
              required=False,
              default=False,
              is_flag=True,
              help="make the match of the words case insensitive.")
@click.option("--get-text",
              required=False,
              default=False,
              is_flag=True,
              help="Log words found on screen regardless of match.")
@click.argument("name")
def assert_text(name: str, no: bool, case_insensitive: bool, get_text: bool):
    """
    Asserts the presence or absence of a specific text string on the
    currently displayed GUI screen.

    :param name: The text string to search for on the screen.
    :type name: str
    :param no: If ``True``, this reverses the assertion, checking that the text
               is *not* found on the screen.
    :type no: bool
    :param case_insensitive: If ``True``, then the search of the text will be
                             case insensitive
    :type case_insensitive: bool
    :return: A string representing the assertion action to be performed by the
             ``gui_run_all`` callback (e.g., ``"assert_text:ExpectedText"`` or
             ``"assert_no_text:UnexpectedText"``).
    :rtype: str
    """
    if no:
        return ("assert_no_text", not case_insensitive, name)
    return ("assert_text", not case_insensitive, get_text, name)


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
@click.argument("path")
def assert_image(path: str, no: bool):
    """
    Asserts the presence or absence of a specific image on the
    currently displayed GUI screen.

    :param path: The text string to search for on the screen.
    :type path: str
    :param no: If ``True``, this reverses the assertion, checking that the text
               is *not* found on the screen.
    :type no: bool
    :return: A string representing the assertion action to be performed by the
             ``gui_run_all`` callback (e.g., ``"assert_image:ImagePath"`` or
             ``"assert_no_image:ImagePath"``).
    :rtype: str
    """
    if no:
        return ("assert_no_image", f"{path}")
    return ("assert_image", f"{path}")


@gui.command()
@click.option("--case-insensitive",
              required=False,
              default=False,
              is_flag=True,
              help="make the match of the words case insensitive.")
@click.argument("name")
def click_on(name: str, case_insensitive: bool):
    """
    Simulates a mouse click action on a GUI object or area that contains the
    specified text.

    :param name: The string text content of the GUI object that should be
                 clicked.
    :type name: str
    :param case_insensitive: If ``True``, then the search of the text will be
                             case insensitive
    :type case_insensitive: bool
    :return: A string representing the click action to be performed by the
             ``gui_run_all`` callback (e.g., ``"click_on:ButtonLabel"``).
    :rtype: str
    """
    return ("click_on", not case_insensitive, name)


@gui.command()
@click.option("--no",
              required=False,
              default=False,
              is_flag=True,
              help="Reverse the action")
def check_home_screen(no: bool):
    """
    Verifies if the currently displayed graphical screen is (or is not) the
    expected "home screen" environment. Currently the Gnome Shell home screen
    from RHEL, CentOS and Fedora is detected.

    :param no: If ``True``, reverses the check to verify that the current screen
               is *not* the home screen.
    :type no: bool
    :return: A string representing the home screen check action to be performed
             by the ``gui_run_all`` callback (e.g., `"check_home_screen"` or
             `"check_no_home_screen"`).
    :rtype: str
    """
    if no:
        return ("check_no_home_screen",)
    return ("check_home_screen",)


@gui.command()
@click.argument("keys")
def kb_send(keys: str):
    """
    Sends one or more specific key press events to the active GUI window.

    :param keys: A string representing the key or sequence of keys to simulate
                 pressing (e.g., ``enter``, ``alt+f4``).
    :type keys: str
    :return: A string representing the keyboard send action to be performed by
             the ``gui_run_all`` callback (e.g., `"kb_send:enter"`).
    :rtype: str
    """
    return ("kb_send", keys)


@gui.command()
@click.argument("keys")
def kb_write(keys: str):
    """
    Simulates typing a literal string of characters into the active GUI input
    field or window. After the string is sent, an 'enter' key press is
    automatically appended.

    :param keys: The string of text to be written or typed into the GUI.
    :type keys: str
    :return: A string representing the keyboard write action to be performed by
             the ``gui_run_all`` callback (e.g., `"kb_write:myusername"`).
    :rtype: str
    """
    return ("kb_write", keys)


@gui.command()
def done():
    """
    Serves as a finalization step for a sequence of GUI test commands.

    :return: A string literal `"done"` that signals the execution of the
             GUI done action within the ``gui_run_all`` callback.
    :rtype: str
    """
    return ("done",)


@gui.result_callback()
@click.pass_context
def gui_run_all(ctx: click.Context,
                actions: list,
                install_missing: bool,
                wait_time: float,
                no_screenshot: bool,
                no_check_difference: bool):
    """
    Executes all chained GUI test actions in the order they were provided on
    the command line. It initializes the graphical
    environment and performs specified GUI automation steps.

    :param ctx: The Click context object.
    :type ctx: click.Context
    :param actions: A list of strings, where each string is a representation
                    of a GUI test action to be performed (e.g., `"init"`,
                    `"assert_text:ExpectedText"`).
    :type actions: list
    :param install_missing: A boolean flag indicating whether any missing
                            packages required for the graphical setup should be
                            installed prior to running the GUI actions.
    :type install_missing: bool
    :param wait_time: Time to wait after running functions
    :type wwait_time: float
    :param no_screenshot: Skip taking screenshots before/after kb_send
    :type no_screenshot: bool
    :param no_check_difference: Skip checking screenshot difference after kb_send
    :type no_check_difference: bool
    :return: This function does not explicitly return a value. It executes
             the GUI test workflow.
    :rtype: None
    """
    ctx.obj["CONTROLLER"].setup_graphical(install_missing, True)

    from SCAutolib.models.gui import GUI
    gui = GUI(from_cli=True,
              wait_time=wait_time,
              screenshot=not no_screenshot,
              check_difference=not no_check_difference)
    for action in actions:
        logger.debug(f"Processing GUI CLI option: {action}...")

        try:
            keyword, *params = action
        except ValueError:
            keyword = action
            params = None

        if keyword == "init":
            gui.__enter__()
        elif keyword == "assert_text":
            case_sensitive, get_text, assert_text = params
            gui.assert_text(assert_text, case_sensitive=case_sensitive,
                            get_text=get_text)
        elif keyword == "assert_no_text":
            case_sensitive, assert_text = params
            gui.assert_no_text(
                assert_text, case_sensitive=case_sensitive)
        elif keyword == "assert_image":
            image, = params
            gui.assert_image(image)
        elif keyword == "assert_no_image":
            image, = params
            gui.assert_no_image(image)
        elif keyword == "click_on":
            case_sensitive, click_on = params
            gui.click_on(click_on, case_sensitive=case_sensitive)
        elif keyword == "check_home_screen":
            gui.check_home_screen()
        elif keyword == "check_no_home_screen":
            gui.check_home_screen(False)
        elif keyword == "kb_send":
            text, = params
            gui.kb_send(text)
        elif keyword == "kb_write":
            text, = params
            gui.kb_write(text)
        elif keyword == "done":
            gui.__exit__(None, None, None)


if __name__ == "__main__":
    cli()
