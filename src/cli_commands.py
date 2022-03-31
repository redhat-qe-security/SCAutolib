import click
from .controller import Controller


@click.command()
def setup_user(env, *args, **kwargs):
    Controller.setup_user(*args, **kwargs)


@click.command()
def create_card():
    Controller.create_card()


@click.command()
def prepare():
    ...
