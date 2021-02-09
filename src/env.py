from shutil import copy, copytree
import subprocess as subp
import logging
import sys
import os

log = logging.getLogger("base")


def setup_ca(**kwargs):
    assert os.path.exists(kwargs["dir"]), "Path is not exist"
    assert os.path.isdir(kwargs["dir"]), "Not a directory"
    log.debug("Start setup of local CA")

    out = subp.run(["bash", "env/setup_ca.sh", "-d", kwargs["dir"]])

    assert out.returncode == 0, "Something break in setup script :("
    log.debug("Setup of local CA is completed")


def cleanup_ca(**kwargs):
    log.debug("Start cleanup of local CA")
    out = subp.run(["bash", "env/cleanup_ca.sh"])

    assert out.returncode == 0, "Something break in setup script :("
    log.debug("Cleanup of local CA is completed")


if __name__ == "__main__":
    assert len(sys.argv) < 4, "Too many input arguments"
    fnc = {"setup_ca": setup_ca, "cleanup_ca": cleanup_ca}
    try:
        name = sys.argv[1]
        dir_path = sys.argv[2]
        fnc[name](dir=dir_path)
    except KeyError as e:
        print("Wrong function name")
        exit(1)
