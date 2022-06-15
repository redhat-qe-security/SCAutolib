"""
This module contains classes that represent configuration files. Each class
contains information and methods to manipulate specific config file except
the parent (File) class that is supposed to operate on general config file.

basic operations on config files defined in this module:
    create: create content of config file usually based on template.
            Note, that some child classes may also update content of config
            file if it already existed and backup original file.
    set:    modify values of config files, add keys or sections
            if necessary
    save:   save modified content to config file
    clean:  remove config file; note that some child classes may also restore
            original config file if backup exists.
"""
from configparser import ConfigParser
from pathlib import Path
from shutil import copy2
from typing import Union

from SCAutolib import TEMPLATES_DIR, LIB_BACKUP
from SCAutolib import logger
import os

class File:
    """
    This class defines an interface for generic operations on config files

    create: create content of config file based on template file
    set:    modify content of config files, add keys or sections if necessary
    save:   save config file
    clean:  remove config file

    Note:   Set method operates on 1) files compatible with ConfigParser (i.e.
            files containing sections); 2) simple config files without sections.
            Other formats of config files are not supported.
    """
    _conf_file = None
    _template = None
    _default_parser = None
    _simple_content = None

    def __init__(self, filepath: Union[str, Path], template: str = None):
        """
        Init of File

        :param filepath: Path of config file
        :type filepath: str or pathlib.Path
        :param template: Path of template file
        :type template: str
        """
        self._conf_file = Path(filepath)
        if template is not None:
            self._template = Path(template)

    @property
    def path(self):
        return self._conf_file

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
            if self._template is None:
                raise FileNotFoundError("Template file was not provided.")
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
        if section is None:
            # simple config files without sections
            if self._simple_content is None:
                with self._conf_file.open() as config:
                    self._simple_content = config.readlines()
            modified = False
            new_content = []
            for line in self._simple_content:
                # skip comments and empty lines
                if line.strip().startswith("#") or len(line.strip()) == 0:
                    new_content.append(line)
                    continue
                try:
                    conf_key, conf_val = line.split("=", 1)
                except ValueError:
                    raise ValueError(f"unexpected format of line: {line}")
                if conf_key.strip() == key:
                    new_content.append(line.replace(conf_val, value + '\n'))
                    modified = True
                else:
                    new_content.append(line)
            if not modified:
                new_content.append(f"\n{key}={value}")
            self._simple_content = new_content
        else:
            # configparser compatible config files (with sections)
            if self._default_parser is None:
                self._default_parser = ConfigParser()
                self._default_parser.optionxform = str
                with self._conf_file.open() as config:
                    self._default_parser.read_file(config)
            if not self._default_parser.has_section(section):
                logger.warning(f"Section {section} not present.")
                logger.info(f"Adding section {section}.")
                self._default_parser.add_section(section)

            previous = self._default_parser.get(section, key,
                                                fallback="Not set")

            self._default_parser.set(section, key, value)
            logger.info("Value is changed.")
            logger.debug(f"Old value in section [{section}] {key}={previous}")
            logger.debug(f"New value in section [{section}] {key}={value}")

    def save(self):
        """
        Save content of config file stored in parser object to config file.
        """
        if self._simple_content is None:
            with self._conf_file.open("w") as config:
                self._default_parser.write(config)
        else:
            with self._conf_file.open("w") as config:
                config.writelines(self._simple_content)

    def clean(self):
        """
        Removes config file
        """
        try:
            self._conf_file.unlink()
            logger.info(f"Removing {self._conf_file}.")
        except FileNotFoundError:
            logger.info(f"{self._conf_file} does not exist. Nothing to do.")


class SSSDConf(File):
    """
    This class contains information and methods to create and modify
    /etc/sssd/sssd.conf file.

    It is implemented as singleton, which allows to use class object
    _default_parser as representation of content of sssd.conf file during
    runtime.

    Intended use is to create/update and save config file in first runtime
    and load content of config file to internal parser object in in following
    runtimes.

    Following methods are implemented:

    create: create a content of internal parser object representing sssd.conf
    set:  set or modify content of internal parser object representing sssd.conf
    save: save content of internal parser object representing sssd.conf to
          /etc/sssd/sssd.conf file
    clean:  restore original state of /etc/sssd/sssd.conf file
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
        Populate internal parser object with content from existing config file
        and update it with values from config template. Back up original files.
        """
        try:
            with self._conf_file.open() as config:
                self._default_parser.read_file(config)
            logger.info(f"{self._conf_file} file exists, loading values")
            logger.info(f"Backing up {self._conf_file}"
                        f"as {self._backup_original}")
            copy2(self._conf_file, self._backup_original)
        except FileNotFoundError:
            logger.warning(f"{self._conf_file} not present")
            logger.warning("Creating sssd.conf based on the template")

        with self._template.open() as template:
            logger.info(f"Updating {self._conf_file} with values from the "
                        f"template")
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
        os.chmod(self._conf_file, 0o600)

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
                logger.error("This suggest that create method was already "
                             "executed. Create method should not be executed "
                             "multiple times")
                raise FileExistsError(f'{file} file exists')


class SoftHSM2Conf(File):
    """
    This class provide information and methods to create and modify
    softhsm2.conf file. Following methods are implemented:

    create: create content of internal file object representing softhsm2.conf
    save:   save content of internal file object representing softhsm2.conf to
            softhsm2.conf file
    """
    _template = Path(TEMPLATES_DIR, "softhsm2.conf")
    _conf_file = None
    _content = None
    _card_dir = None

    def __init__(self, filepath: Union[str, Path], card_dir: Union[str, Path]):
        """
        Init of SoftHSM2Conf

        :param filepath: path where config file should be saved
        :type filepath: str
        :param card_dir: parameter to be updated in config file
        :type card_dir: str
        """
        self._conf_file = filepath if isinstance(filepath, Path) else \
            Path(filepath)
        self._card_dir = card_dir if isinstance(card_dir, Path) else \
            Path(card_dir)

    def create(self):
        """
        Populate internal file object with content based on template.
        """
        with self._template.open('r') as template:
            self._content = template.read().format(card_dir=self._card_dir)

        logger.info(f"Creating content of {self._conf_file} "
                    f"based on {self._template}")

    def set(self, *args):
        """
        Raise NotImplementedError as set method for softHSM2 is not implemented
        """
        # parent class set method does not work as softHSM2 conf does not have
        # sections. Method do modify softHSM2 conf is not implemented
        logger.warning("softhsm2.conf does not contain sections.")
        raise NotImplementedError("softHSM2conf.set method not implemented")

    def save(self):
        """
        Save content stored in internal file object to config file.
        """
        with self._conf_file.open("w") as config:
            config.write(self._content)
        logger.debug(f"Config file {self._conf_file} is created")


class OpensslCnf(File):
    """
    This class provides information and methods to create and modify
    openssl cnf files. Following methods are implemented:

    create: create content of internal file object representing openssl cnf file
    save:  save content of internal file object representing openssl cnf file to
           .cnf file specified by user
    """
    _template = None
    _conf_file = None
    _content = None
    _old_string = None
    _new_string = None

    # openssl cnf content depends substantially on its purpose and separate
    # templates are needed for specific config files types. mapping:
    types = {
        "CA": {"template": Path(TEMPLATES_DIR, 'ca.cnf'),
               "replace": "{ROOT_DIR}"},
        "user": {"template": Path(TEMPLATES_DIR, 'user.cnf'),
                 "replace": "{user}"}
    }

    def __init__(self, filepath: Union[str, Path], conf_type: str,
                 replace: str):
        """
        Init of opensslCNF

        :param filepath: Path of config file
        :type filepath: str or pathlib.Path
        :param conf_type: Identifier of cnf file
        :type conf_type: basestring
        :param replace: string that will replace specific string from template
        :type replace: str
        """
        self._conf_file = Path(filepath)
        self._template = Path(self.types[conf_type]["template"])
        self._old_string = self.types[conf_type]["replace"]
        self._new_string = replace

    def create(self):
        """
        Populate internal file object with content based on template
        and update specific strings
        """
        with self._template.open('r') as template:
            template_content = template.read()
        self._content = template_content.replace(self._old_string,
                                                 self._new_string)

    def save(self):
        """
        Save content stored in internal file object to config file.
        """
        with self._conf_file.open("w") as config:
            if self._default_parser is None:
                config.write(self._content)
            else:
                # in case set method was used
                self._default_parser.write(config)

    @property
    def path(self):
        return self._conf_file
