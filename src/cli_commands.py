import click
from .controller import *


@click.command()
def setup_user(env, *args, **kwargs):
    setup_user_(*args, **kwargs)


@click.command()
def create_card():
    create_card_()


@click.command()
def prepare():
    ...
