from os.path import (dirname, abspath, join)

import yaml
from SCAutolib import env_logger
from decouple import config

DIR_PATH = dirname(abspath(__file__))
SETUP_IPA_SERVER = f"{DIR_PATH}/env/ipa-install-server.sh"


def load_env(conf_file: str) -> str:
    """
    Create .env near source files of the library. In .env file following
    variables expected to be present: CA_DIR, TMP, KEYS, CERTS, BACKUP.
    Deployment process would relay on this variables.

    Args:
        conf_file: path to YAML configuration fil
    Returns:
        Path to .env file.
    """

    env_file = f"{DIR_PATH}/.env"
    with open(conf_file, "r") as f:
        env_logger.debug(f"Reading configurations from {conf_file}")
        data = yaml.load(f, Loader=yaml.FullLoader)
        ca_dir = data["ca_dir"]
    data["restore"] = []

    with open(conf_file, "w") as f:
        yaml.dump(data, f)
        env_logger.debug("restore section is added to te configuration file")

    with open(env_file, "w") as f:
        f.write(f"TMP={join(ca_dir, 'tmp')}\n")
        f.write(f"KEYS={join(ca_dir, 'tmp', 'keys')}\n")
        f.write(f"CERTS={join(ca_dir, 'tmp', 'certs')}\n")
        f.write(f"BACKUP={join(ca_dir, 'tmp', 'backup')}\n")
        f.write(f"CONF={abspath(conf_file)}\n")
        f.write(f"CA_DIR={ca_dir}\n")
    env_logger.debug(f"File {env_file} is created")
    return env_file


def read_env(item: str, *args, **kwargs):
    """Just for unifying with read_conf function. Accepts all arguments that
    decouple.config() function takes.
    Args:
        item: variable to read from the .env file
    """
    return config(item, *args, **kwargs)


def read_config(*items) -> list or object:
    """
    Read data from the configuration file and return require items or full
    content.

    Args:
        items: list of items to extracrt from the configuration file.
               If None, full contant would be returned

    Returns:
        list with required items
    """
    try:
        with open(read_env("CONF"), "r") as file:
            config_data = yaml.load(file, Loader=yaml.FullLoader)
            assert config_data, "Data are not loaded correctly."
    except FileNotFoundError as e:
        env_logger.error(".env file is not present. Try to rerun command"
                         "with --conf </path/to/conf.yaml> parameter")
        raise e

    if items is None:
        return config_data

    return_list = []
    for item in items:
        parts = item.split(".")
        value = config_data
        for part in parts:
            if value is None:
                env_logger.warning(
                    f"Key {part} not present in the configuration file. Skip.")
                return None

            value = value.get(part)
            if part == parts[-1]:
                return_list.append(value)

    return return_list if len(items) > 1 else return_list[0]
