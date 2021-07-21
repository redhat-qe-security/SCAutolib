from os.path import (dirname, abspath, join, exists)
from SCAutolib.src import env

import yaml

from SCAutolib import env_logger

DIR_PATH = dirname(abspath(__file__))
SETUP_CA = f"{DIR_PATH}/env/setup_ca.sh"
SETUP_VSC = f"{DIR_PATH}/env/setup_virt_card.sh"
CLEANUP_CA = f"{DIR_PATH}/env/cleanup_ca.sh"
DOTENV = f"{DIR_PATH}/.env"
CA_DIR = None
TMP = None
CONF_DIR = None
KEYS = None
CERTS = None
BACKUP = None
CONFIG_DATA = None  # for caching configuration data
KRB_IP = None
CONF = None


def load_env(conf_file: str) -> str:
    """
    Create .env near source files of the library. In .env file following
    variables expected to be present: CA_DIR, CONF_DIR, TMP, KEYS, CERTS, BACKUP.
    Deployment process would relay on this variables.

    Args:
        conf_file: path to YAML configuration fil
    Returns:
        Path to .env file.
    """

    env_file = f"{DIR_PATH}/.env"
    if not exists(env_file):
        env_logger.debug(f"File {env_file} does not exist. Creating...")
        with open(conf_file, "r") as f:
            env_logger.debug(f"Reading configurations from {conf_file}")
            data = yaml.load(f, Loader=yaml.FullLoader)
            ca_dir = data["ca_dir"]
        conf_file = conf_file.split("/")[-1]

        with open(env_file, "w") as f:
            f.write(f"TMP={join(ca_dir, 'tmp')}\n")
            f.write(f"CONF_DIR={join(ca_dir, 'conf')}\n")
            f.write(f"KEYS={join(ca_dir, 'tmp', 'keys')}\n")
            f.write(f"CERTS={join(ca_dir, 'tmp', 'certs')}\n")
            f.write(f"BACKUP={join(ca_dir, 'tmp', 'backup')}\n")
            f.write(f"CONF={conf_file}\n")
            f.write(f"CA_DIR={ca_dir}\n")
            env_logger
    return env_file
