"""
Here we implement all CLI API. These functions are wrappers for methods in
Controller class.

Check documentation for CLI commands in ``scauto --help`` after
:ref:`installation<SCAutolib installation!>`.

"""

import click
from .controller import Controller


@click.group()
def cli():
    pass


@click.command()
def setup_user(env, *args, **kwargs):
    Controller.setup_user(*args, **kwargs)


@click.command()
def create_card():
    Controller.create_card()


@click.command()
def prepare():
    ...


@click.command()
def hello_world():
    print("Just check that CLI commands works")


cli.add_command(hello_world)
cli.add_command(create_card)
cli.add_command(prepare)
