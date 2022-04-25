"""
This module provide information and methods to create and modify
/etc/sssd/sssd.conf file. Following methods are implemented:

create: create content of internal parser object representing sssd.conf
set:    set or modify content of internal parser object representing sssd.conf
save:   save content of internal parser object representing sssd.conf to
        /etc/sssd/sssd.conf file
clean:  restore original state of /etc/sssd/sssd.conf file
"""

from configparser import ConfigParser
from pathlib import Path
from shutil import copy2
from typing import Union

from SCAutolib import TEMPLATES_DIR, LIB_BACKUP
from SCAutolib import logger
from SCAutolib.models.file import File


class SSSDConf(File):
    """
    This class contains information and methods to handle sssd.conf file

    It is implemented as singleton, which allows to use class object
    _default_parser as representation of content of sssd.conf file during
    runtime.

    Intended use is to create/update and save config file in first runtime
    and load content of config file to internal parser object in in following
    runtimes.
    """
    __instance = None
    _template = Path(TEMPLATES_DIR, "sssd.conf")
    _conf_file = Path("/etc/sssd/sssd.conf")
    _backup_original = Path(LIB_BACKUP, 'original_sssd.conf')
    _backup_default = Path(LIB_BACKUP, 'default_sssd.conf')

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super(SSSDConf, cls).__new__(cls)
            cls.__instance.__initialized = False
        return cls.__instance

    def __init__(self):
        if self.__initialized:
            return
        self.__initialized = True

        # _default_parser object stores default content of config file
        self._default_parser = ConfigParser()
        # avoid problems with inserting some 'specific' values
        self._default_parser.optionxform = str

        if self._backup_default.exists():
            with self._backup_default.open() as config:
                self._default_parser.read_file(config)

        # _changes parser object reflects modifications imposed by set method
        self._changes = ConfigParser()
        self._changes.optionxform = str

    def create(self):
        """
        Populate internal parser object with content from existing config file and
        update it with values from config template. Back up original files.
        """
        try:
            with self._conf_file.open() as config:
                self._default_parser.read_file(config)
            logger.info(f"{self._conf_file} file exists, loading values")
            logger.info(f"Backing up {self._conf_file} as {self._backup_original}")
            copy2(self._conf_file, self._backup_original)
        except FileNotFoundError:
            logger.warning(f"{self._conf_file} not present")
            logger.warning("Creating sssd.conf based on the template")

        with self._template.open() as template:
            logger.info(f"Updating {self._conf_file} with values from the template")
            self._default_parser.read_file(template)

        with self._backup_default.open("w") as bdefault:
            self._default_parser.write(bdefault)

    def set(self, key: str, value: Union[int, str, bool], section: str = None):
        """
        Modify or add content of config file represented by ConfigParser object

        :param key: key from section of config file to be updated
        :type key: str
        :param value: new value to be stored in [section][key] of config file
        :type value: int or bool or str
        :param section: section of config file to be created/updated
        :type section: str
        """
        if len(self._changes.sections()) == 0:
            self._changes.read_dict(self._default_parser)

        if not self._changes.has_section(section):
            logger.warning(f"Section {section} not present.")
            logger.info(f"Adding section {section}.")
            self._changes.add_section(section)

        previous = self._changes.get(section, key, fallback="Not set")

        self._changes.set(section, key, value)
        logger.info(f"Value is changed in section {self._changes[section]}")
        logger.debug(f"Old value in section [{section}] {key}={previous}")
        logger.debug(f"New value in section [{section}] {key}={value}")

    def save(self):
        """
        Save content of config file stored in parser object to config file.
        """
        with self._conf_file.open("w") as config:
            if len(self._changes.sections()) == 0:
                # after create; _changes is empty; content is in _default_parser
                self._default_parser.write(config)
            else:
                # after set; _changes reflects current content
                self._changes.write(config)
                # re-initialization because I did not find other simple way
                # to empty parser object
                self._changes = ConfigParser()
                self._changes.optionxform = str

    def clean(self):
        """
        Removes sssd.conf file in case it was created by this package or
        restore original sssd.conf in case the file was modified.
        """
        if self._backup_original.exists():
            copy2(self._backup_original, self._conf_file)
        else:
            self._conf_file.unlink()

    def _update_default_content(self):
        """
        Populate internal parser object with content from current config file.
        """
        self._default_parser = ConfigParser()
        self._default_parser.optionxform = str
        with self._conf_file.open() as config:
            self._default_parser.read_file(config)
        logger.info(f"Backing up {self._conf_file} as {self._backup_default}")
        copy2(self._conf_file, self._backup_default)

    def check_backups(self):
        """
        Raises an exception if internal backup files already exists
        """
        backup_files = (self._backup_default, self._backup_original)
        for file in backup_files:
            if file.exists():
                logger.error(f"Backup of {file} already exists")
                logger.error("This suggest that create method was already executed"
                             "Create method should not be executed multiple times")
                raise FileExistsError(f'{file} file exists')
