import logging
import subprocess
from os import symlink
from os.path import (dirname, abspath, join, exists)
from pathlib import Path

import coloredlogs
import yaml

logger = logging.getLogger(__name__)
fmt = "%(module)s.%(funcName)s.%(lineno)d [%(levelname)s] %(message)s"
date_fmt = "%H:%M:%S"
coloredlogs.install(level="DEBUG", fmt=fmt, datefmt=date_fmt,
                    field_styles={'levelname': {'bold': True, 'color': 'blue'}})

DIR_PATH = dirname(abspath(__file__))
TEMPLATES_DIR = Path(DIR_PATH, "templates")

SETUP_IPA_SERVER = f"{DIR_PATH}/env/ipa-install-server.sh"
LIB_DIR = "/etc/SCAutolib"
CONF = join(LIB_DIR, "user-conf.yaml")
LIB_CONF = join(LIB_DIR, "lib-conf.yaml")
LIB_CA = join(LIB_DIR, "ca")
LIB_BACKUP = join(LIB_DIR, "backup")
LIB_KEYS = join(LIB_DIR, "keys")
LIB_CERTS = join(LIB_DIR, "certs")


def init_config(user_config=None, config_content: dict = None):
    """Initialize configuration files to be used in the library. Function
    creates internal library configuration file for storing internal values
    to share them between different phases and creates symlink to user
    configuration file to access it in standard way

    :param user_config: path to user configuration file
    :param config_content: content to be inserted into library internal
                           config file. If not provided, default content
                           would be generated.
    """
    logger.debug("Initializing configuration file")
    if not exists(LIB_DIR):
        Path(LIB_DIR).mkdir(parents=True, exist_ok=True)
    if not exists(LIB_CONF):
        logger.debug("Library configuration file does not exists. "
                     "Creating...")
        if config_content is None:
            config_content = {"restore": [], "ready": False}
            logger.debug(f"Default configuration is used: {config_content}")

        with open(LIB_CONF, "w") as f:
            yaml.dump(config_content, f)
        logger.debug("Library internal configuration file is created in "
                     f"{LIB_CONF}")
    if not exists(CONF) and user_config is not None:
        symlink(user_config, CONF)
        logger.warning("Symlink to user configuration is updated "
                       f"{CONF} -> {user_config}")


def read_config(*items, cast=None, which="user", config_file=None) \
        -> list or object:
    """
    Read data from the configuration file and return require items or full
    content.

    :param items: list of items to extract from the configuration file.
           If None, full content would be returned
    :param cast: data type to cast value to
    :param which: define which configuration file to read: library
                  internal or user configuration file
    :param config_file: path to custom specific file in YAML format to read from

    :return: list with required items
    """
    if config_file is None:
        config_file = CONF if which == "user" else LIB_CONF
    with open(config_file, "r") as file:
        config_data = yaml.load(file, Loader=yaml.FullLoader)
        assert config_data, "Data are not loaded correctly."

    if len(items) == 0:
        return config_data

    return_list = []
    for item in items:
        parts = item.split(".")
        value = config_data
        for part in parts:
            if value is None:
                logger.warning(
                    f"Key {part} not present in the configuration file. Skip.")
                return None

            value = value.get(part)
            if part == parts[-1]:
                if cast is not None:
                    value = cast(value)
                return_list.append(value)

    return return_list if len(items) > 1 else return_list[0]


def set_config(path, value, action="replace", type_=str):
    """Sets field to given value in configuration file.

    :param path: path in the configuration file in doted notation (a.b.c). If
                 any of path part doesn't exist, then it would be created.
    :param value: value to be set for last key in path
    :param action: action for value. By default, is "replace". If "append", then
                   given value would be appended to the list of value for the
                   last key in the path.
    :param type_: data type to which value would be converted and inserted to
                  configuration file. By default, is "str".
    """
    logger.debug(f"Reading configuration from {LIB_CONF}")

    config_data = {}
    if exists(LIB_CONF):
        with open(LIB_CONF, "r") as file:
            config_data = yaml.load(file, Loader=yaml.FullLoader)
    obj = config_data
    key_list = path.split(".")

    for k in key_list[:-1]:
        if k not in obj.keys():
            logger.warning(f"Key {k} is not present in the configuration "
                           f"file. This key would be added.")
            obj[k] = dict()
        obj = obj[k]

    try:
        if value is not None:
            value = type_(value)
    except ValueError:
        logger.error(f"Cant convert value {value} of type "
                     f"{str(type(value))} to type {str(type_)}")

    if action == "replace":
        obj[key_list[-1]] = value

    elif action == "append":
        if type(obj[key_list[-1]]) == list:
            obj[key_list[-1]].append(value)
        else:
            obj[key_list[-1]] = [obj[key_list[-1]], value]

    with open(LIB_CONF, "w") as f:
        yaml.dump(config_data, f)

    logger.debug(f"Value for filed {path} is update to {value}")


def run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        print_=True, *args, **kwargs) -> subprocess.CompletedProcess:
    if type(cmd) == str:
        cmd = cmd.split(" ")
    out = subprocess.run(cmd, stdout=stdout, stderr=stderr, encoding="utf-8",
                         *args, **kwargs)
    if print_:
        if out.stdout != "":
            logger.debug(out.stdout)
        if out.stderr != "":
            logger.warning(out.stderr)

    if check and out.returncode != 0:
        raise subprocess.CalledProcessError(out.returncode, cmd)
    return out
