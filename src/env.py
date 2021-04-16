import logging
from os.path import (exists, realpath, isdir,
                     isfile, dirname, abspath)
import click
import yaml
import subprocess as subp

log = logging.getLogger("base")

# TODO add docs about parameters
path = dirname(abspath(__file__))
SETUP_CA = f"{path}/env/setup_ca.sh"
SETUP_VSC = f"{path}/env/setup_virt_card.sh"
CLEANUP_CA = f"{path}/env/cleanup_ca.sh"


@click.group()
def cli():
    pass


@click.command()
@click.option("--path", "-p", type=click.Path(), help="Path to working directory")
@click.option("--conf", "-c", type=click.Path(), help="Path to YAML file with configurations")
def setup_ca(path, conf):
    """
    Call bash sript for settingup the local CA.
    """
    assert exists(path), f"Path {path} is not exist"
    assert isdir(path), f"{path} is not a directory"
    assert exists(realpath(conf)), f"File {conf} is not exist"
    assert isfile(realpath(conf)), f"{conf} is not a file"

    log.debug("Start setup of local CA")

    with open(conf, "r") as file:
        data = yaml.load(file, Loader=yaml.FullLoader)
        user = data["variables"]["user"]
        out = subp.run(["bash", SETUP_CA, "--dir", path,
                        "--username", user["name"],
                        "--userpasswd", user["passwd"],
                        "--pin", user["pin"]])
        assert out.returncode == 0, "Something break in setup playbook :("
        log.debug("Setup of local CA is completed")


@click.command()
@click.option("--conf", "-c", type=click.Path())
@click.option("--work-dir", "-w", type=click.Path())
def setup_virt_card(conf, work_dir):
    assert exists(conf), f"Path {conf} is not exist"
    assert isdir(conf), f"{conf} Not a directory"
    assert exists(work_dir), f"Path {work_dir} is not exist"
    assert isdir(work_dir), f"{work_dir} Not a directory"

    log.debug("Start setup of local CA")
    out = subp.run(["bash", SETUP_VSC, "-c", conf, "-w", work_dir])

    assert out.returncode == 0, "Something break in setup playbook :("
    log.debug("Setup of local CA is completed")


@click.command()
def cleanup_ca():
    log.debug("Start cleanup of local CA")
    out = subp.run(
        ["bash", CLEANUP_CA])

    assert out.returncode == 0, "Something break in setup script :("
    log.debug("Cleanup of local CA is completed")


cli.add_command(setup_ca)
cli.add_command(setup_virt_card)
cli.add_command(cleanup_ca)

if __name__ == "__main__":
    cli()
