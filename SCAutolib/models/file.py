"""
General operations with generic config files.

This module serves as an interface and defines basic operations
on config files:
    create: create content of config file usually based on template.
            Note, that some child classes may also update content of config
            file if it already existed.
    set:    modify values of config files, add keys or sections
            if necessary
    save:   save modified content to config file
    clean:  remove config file; note that some child classes may also restore
            original config file if backup exists.
"""
from configparser import ConfigParser
from pathlib import Path
from typing import Union

from SCAutolib import logger


class File:
    """
    This class defines an interface for generic operations on config files

    create: create content of config file based on template file
    set:    modify content of config files, add keys or sections if necessary
    save:   save config file
    clean:  remove config file
    """
    _conf_file = None
    _template = None
    _default_parser = None

    def __init__(self, filepath: Union[str, Path], template: str = None):
        """
        Init of File

        :param filepath: Path of config file
        :type filepath: str of pathlib.Path
        :param template: Path of template file
        :type template: str
        """
        self._conf_file = Path(filepath)
        if template is not None:
            self._template = Path(template)

    def create(self):
        """
        Populate internal parser object with content based on template.
        """
        if self._conf_file.exists():
            logger.warning(f"Create error: {self._conf_file} already exists.")
            raise FileExistsError(f'{self._conf_file} already exists')
        else:
            self._default_parser = ConfigParser()
            self._default_parser.optionxform = str
            with self._template.open() as t:
                self._default_parser.read_file(t)

    def set(self, key: str, value: Union[int, str, bool], section: str = None):
        """
        Modify value in config file.

        :param key: value for this key will be updated
        :type key: str
        :param value: new value to be stored in [section][key] of config file
        :type value: int or str or bool
        :param section: section of config file that will be modified
        :type section: str
        """
        if self._default_parser is None:
            self._default_parser = ConfigParser()
            self._default_parser.optionxform = str
            with self._conf_file.open() as config:
                self._default_parser.read_file(config)
        if not self._default_parser.has_section(section):
            logger.warning(f"Section {section} not present.")
            logger.info(f"Adding section {section}.")
            self._default_parser.add_section(section)

        previous = self._default_parser.get(section, key, fallback="Not set")

        self._default_parser.set(section, key, value)
        logger.info(f"Value is changed.")
        logger.debug(f"Old value in section [{section}] {key}={previous}")
        logger.debug(f"New value in section [{section}] {key}={value}")

    def save(self):
        """
        Save content of config file stored in parser object to config file.
        """
        with self._conf_file.open("w") as config:
            self._default_parser.write(config)

    def clean(self):
        """
        Removes config file
        """
        try:
            self._conf_file.unlink()
            logger.info(f"Removing {self._conf_file}.")
        except FileNotFoundError:
            logger.info(f"{self._conf_file} does not exist. Nothing to do.")
