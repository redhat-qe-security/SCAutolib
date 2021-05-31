from decouple import config
from os.path import (dirname, abspath, join)
from shutil import copy
from SCAutolib import env_logger

DIR_PATH = dirname(abspath(__file__))
SETUP_CA = f"{DIR_PATH}/env/setup_ca.sh"
SETUP_VSC = f"{DIR_PATH}/env/setup_virt_card.sh"
CLEANUP_CA = f"{DIR_PATH}/env/cleanup_ca.sh"
WORK_DIR = None
TMP = None
CONF_DIR = None
KEYS = None
CERTS = None
BACKUP = None
CONFIG_DATA = None  # for caching configuration data
KRB_IP = None
CONF = None


def load_env(env_file, conf_file, work_dir=join(DIR_PATH, "virt_card")) -> str:
    """
    Create .env near source files of the libarary. In .env file following
    variables expected to be present: WORK_DIR, CONF_DIR, TMP, KEYS, CERTS, BACKUP.
    Deployment process would relay on this variables.

    Args:
        conf_file: path to YAML configuration file
        env_file:  path to already existing .env file. If given, then it would
                   be just copied to the library.
        work_dir: working directory

    Returns:
        Path to .env file.
    """
    global WORK_DIR
    global CONF
    global CONF_DIR
    global BACKUP
    if env_file is None:
        env_file = f"{DIR_PATH}/.env"
        with open(env_file, "w") as f:
            f.write(f"WORK_DIR={work_dir}\n")
            f.write(f"TMP={join(work_dir, 'tmp')}\n")
            f.write(f"CONF_DIR={join(work_dir, 'conf')}\n")
            f.write(f"KEYS={join(work_dir, 'tmp', 'keys')}\n")
            f.write(f"CERTS={join(work_dir, 'tmp', 'certs')}\n")
            f.write(f"BACKUP={join(work_dir, 'tmp', 'backup')}\n")
            f.write(f"CONF={conf_file}")
    else:
        # .env file should be near source file
        # because this env file is used other source files
        copy(env_file, DIR_PATH)
        env_file = join(DIR_PATH, ".env")
    env_logger.debug("Environment file is created")
    WORK_DIR = work_dir
    CONF_DIR = config("CONF_DIR", cast=str)
    BACKUP = config("BACKUP", cast=str)
    CONF = conf_file

    return env_file


def check_env():
    """
    Insure that environment variables are loaded from .env file.
    """
    global BACKUP
    global KEYS
    global CERTS
    global TMP
    global CONF_DIR
    global WORK_DIR
    global CONF

    if WORK_DIR is None:
        WORK_DIR = config("WORK_DIR")
    if BACKUP is None:
        BACKUP = config("BACKUP")
    if KEYS is None:
        KEYS = config("KEYS")
    if CERTS is None:
        CERTS = config("CERTS")
    if TMP is None:
        CERTS = config("TMP")
    if CONF_DIR is None:
        CONF_DIR = config("CONF_DIR")
    if CONF is None:
        CONF = config("CONF")
