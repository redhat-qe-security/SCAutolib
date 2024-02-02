"""
This module contains classes that represent configuration files. Each class
contains information and methods to manipulate specific config file except
the parent (File) class that is supposed to operate on general config file.

Basic operations on config files defined in this module:
    * create
        creates content of config file usually based on template.
        Note, that some child classes may also update content of config
        file if it already existed and backup original file.
    * set
        modify values of config files, add keys or sections if necessary
    * save
        save modified content to config file
    * clean
        remove config file; note that some child classes may also restore
        original config file if backup exists.
"""
import os
from configparser import ConfigParser
from pathlib import Path
from shutil import copy2
from traceback import format_exc
from typing import Union
import json

from SCAutolib import logger, TEMPLATES_DIR, LIB_BACKUP, LIB_DUMP_CONFS, run
from SCAutolib.exceptions import SCAutolibException


class File:
    """
    This class defines an interface for generic operations on config files

    * create: create content of config file based on template file
    * set:    modify content of config files, add keys or sections if necessary
    * save:   save config file
    * clean:  remove config file

    .. note:: Set method operates **only** on:

     * files compatible with ConfigParser (i.e. files containing sections)
     * simple config files without sections.

     Other formats of config files are not supported.
    """
    _conf_file = None
    _template = None
    _default_parser = None
    _simple_content = None

    def __init__(self, filepath: Union[str, Path], template: Path = None):
        """
        Init of File

        :param filepath: Path of config file
        :type filepath: str or pathlib.Path
        :param template: Path of template file
        :type template: str
        """
        self._conf_file = Path(filepath)
        if template is not None:
            self._template = template

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

    def set(self, key: str, value: Union[int, str, bool], section: str = None,
            separator: str = "="):
        """
        Modify value in config file. Modification is made through the
        ConfigParser object if it is defined. If not, then key value pair
        would be written to the file through normal :code:`write()` method with
        composed string in the following form :code:`<key><separator><value>`

        .. note::
            spaces around key has to be specified as a part of the
            :code:`separator` parameter.

        :param key: value for this key will be updated
        :type key: str
        :param value: new value to be stored in [section][key] of config file
        :type value: int or str or bool
        :param section: section of config file that will be modified
        :type section: str
        :param separator: Character to be used as a separator between key and
            value in files that are not supported by ConfigParser object.
        :type separator: str

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
                    conf_key, conf_val = line.split(separator, 1)
                except ValueError:
                    raise ValueError(f"unexpected format of line: {line}")
                if conf_key.strip() == key:
                    new_content.append(line.replace(conf_val, value + '\n'))
                    modified = True
                else:
                    new_content.append(line)
            if not modified:
                new_content.append(f"\n{key}{separator}{value}")
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

    def get(self, key, section: str = None, separator: str = "="):
        """
        Method processes and returns the value of the key in section. If the
        section is not provided (section=None), then file would be parsed line
        by line splitting the line on separator. First match wins and is
        returned.

        If section is provided and the file can be parsed by the
        :code:`ConfigParser`, then this object would be used to look for the
        key.

        :param key: required key
        :param section: section where the key should be found
        :param separator: applicable only for non-configparser file. Separator
            that would be used to so split a line from the file. By default
            separator is '='
        :raise SCAutolib.SCAutolibException: if the key is not found the
            non-ConfigParser file
        :raise configparser.NoSectionError: if the section is not found in
            ConfigParser-supported file
        :raise KeyError: if the key is not present in ConfigParser-supported
            file
        :return: value of the key in section (if set)
        """
        if section is None:
            # simple config files without sections
            if self._simple_content is None:
                with self._conf_file.open() as config:
                    self._simple_content = config.readlines()
            for line in self._simple_content:
                if line.strip().startswith("#") or line.strip() == "":
                    continue
                key_from_file, value = line.split(separator, maxsplit=1)
                if key_from_file == key:
                    return value.strip()

            raise SCAutolibException(f"Key '{key}' doesn't present in the "
                                     f"file {self._conf_file}")
        elif self._default_parser is None:
            self._default_parser = ConfigParser()
            self._default_parser.optionxform = str
            with self._conf_file.open() as config:
                self._default_parser.read_file(config)
        return self._default_parser[section][key]

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

    def backup(self, name: str = None):
        """
        Save original file to the backup directory with given name. If name is
        None, default name is :code:`<filename>.<extension>.backup`

        :param name: custom file name to be set for the file
        :type name: str
        :return: path where the file is stored
        """

        new_path = LIB_BACKUP.joinpath(
            f"{name if name else self._conf_file.name}.backup")
        copy2(self._conf_file, new_path)
        logger.debug(f"File {self._conf_file} is stored to {new_path}")
        self._backup = {"original": str(self._conf_file),
                        "backup": str(new_path)}
        return new_path

    def restore(self, name: str = None):
        """
        Copies backup file to original file location.
        """
        original_path = LIB_BACKUP.joinpath(
            f"{name if name else self._conf_file.name}.backup")

        if original_path.exists():
            with self._conf_file.open("w") as config, \
                    original_path.open() as backup:
                config.write(backup.read())
            original_path.unlink()
            logger.debug(
                f"File {self._conf_file} is restored to {original_path}"
            )


class SSSDConf(File):
    """
    This class contains information and methods to create and modify
    /etc/sssd/sssd.conf file.

    It is implemented as singleton, which allows to use class object
    :code:`_default_parser` as representation of content of sssd.conf file
    during runtime.

    Intended use is to create/update and save config file in first runtime
    and load content of config file to internal parser object in following
    runtimes.
    """
    __instance = None
    _template = Path(TEMPLATES_DIR, "sssd.conf")
    _conf_file = Path("/etc/sssd/sssd.conf")
    _backup_original = None
    _backup_default = LIB_BACKUP.joinpath('default-sssd.conf')
    _backup_current_cont = None
    _before_last_change_cont = None
    _changed = False

    dump_file: Path = LIB_DUMP_CONFS.joinpath("SSSDConf.json")

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

        if self.dump_file.exists():
            with self.dump_file.open("r") as f:
                cnt = json.load(f)
                self._backup_original = Path(cnt['_backup_original'])

    def __call__(self, key: str, value: Union[int, str, bool],
                 section: str = None):
        # We need to save the state of the current unchanged sssd.conf because
        # __call__ is called before __enter__ in
        # with SSSDConf(key, value, section):
        with self._conf_file.open() as config:
            self._before_last_change_cont = config.read()

        self.set(key, value, section)
        self.save()
        run("systemctl restart sssd", sleep=10)
        return self

    def __enter__(self):
        # Check if we changed the file or not and save version before context
        # manager was called
        if self._before_last_change_cont:
            self._backup_current_cont = self._before_last_change_cont
        else:
            with self._conf_file.open() as config:
                self._backup_current_cont = config.read()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._changed:
            # Restore sssd.conf to the version before context manager was
            # called
            with self._conf_file.open("w") as config:
                config.write(self._backup_current_cont)
            self._backup_current_cont = None
            self._before_last_change_cont = None
            self._changed = False
        if exc_type is not None:
            logger.error("Exception in virtual smart card context")
            logger.error(format_exc())
        run("systemctl restart sssd", sleep=10)

    def create(self):
        """
        Populate internal parser object with content from existing config file
        and update it with values from config template. Back up original files.
        """
        try:
            with self._conf_file.open() as config:
                self._default_parser.read_file(config)
            logger.info(f"{self._conf_file} file exists, loading values")
            self._backup_original = self.backup("sssd-conf-original")

        except FileNotFoundError:
            logger.warning(f"{self._conf_file} not present")
            logger.warning("Creating sssd.conf based on the template")

        with self._template.open() as template:
            logger.info(f"Updating {self._conf_file} with values from the "
                        f"template")
            self._default_parser.read_file(template)

        with self._backup_default.open("w") as bdefault:
            self._default_parser.write(bdefault)

        with self.dump_file.open("w") as f:
            json.dump({
                "_backup_original": str(self._backup_original)
            }, f)

    def set(self, key: str, value: Union[int, str, bool], section: str = None):
        """
        Modify or add content of config file represented by ConfigParser object

        If a value is set outside of a context manager, it is the user's
        responsibility to revert it.

        :param key: key from section of config file to be updated
        :type key: str
        :param value: new value to be stored in [section][key] of config file
        :type value: int or bool or str
        :param section: section of config file to be created/updated
        :type section: str
        """
        if len(self._changes.sections()) == 0:
            with self._conf_file.open() as config:
                self._changes.read_file(config)

        if not self._changes.has_section(section):
            logger.warning(f"Section {section} not present.")
            logger.info(f"Adding section {section}.")
            self._changes.add_section(section)

        previous = self._changes.get(section, key, fallback="Not set")
        if previous == value:
            logger.info(f"A key '{key}' in section '{section}' is already set "
                        f"to {value}. No changes in SSSD are required.")
            return

        self._changes.set(section, key, value)
        self._changed = True

        logger.info(f"Value is changed in section {self._changes[section]}")
        logger.debug(f"Old value in section [{section}] {key}={previous}")
        logger.debug(f"New value in section [{section}] {key}={value}")

    def save(self):
        """
        Save content of config file stored in parser object to config file.

        .. note: SSSD service restart is caller's responsibility.
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

    def restore(self):
        """
        Removes sssd.conf file in case it was created by this package or
        restore original sssd.conf in case the file was modified.

        .. note: SSSD service restart is caller's responsibility.
        """

        if self._backup_original and self._backup_original.exists():
            with self._backup_original.open() as original, \
                    self._conf_file.open("w") as config:
                config.write(original.read())
            self._backup_original.unlink()
        else:
            self.clean()

        if self._backup_default.exists():
            self._backup_default.unlink()

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

        logger.info("Restored sssd.conf to the original version")
        self._changed = False

    def update_default_content(self):
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
    softhsm2.conf file.
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
        :raise NotImplementedError: if this method is called on SoftHSM2Conf.
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
    openssl cnf files.
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
               "replace": ["{ROOT_DIR}"]},
        "user": {"template": Path(TEMPLATES_DIR, 'user.cnf'),
                 "replace": ["{user}", "{cn}"]}
    }

    def __init__(self, filepath: Union[str, Path], conf_type: str,
                 replace: Union[str, list]):
        """
        Init of opensslCNF

        :param filepath: Path of config file
        :type filepath: str or pathlib.Path
        :param conf_type: Identifier of cnf file
        :type conf_type: basestring
        :param replace: list of strings that will replace specific strings from
                        template
        :type replace: list
        """
        self._conf_file = Path(filepath)
        self._template = Path(self.types[conf_type]["template"])
        self._old_strings = self.types[conf_type]["replace"]
        if isinstance(replace, str):
            replace = [replace]
        self._new_strings = replace

    def create(self):
        """
        Populate internal file object with content based on template
        and update specific strings
        """
        with self._template.open('r') as template:
            self._content = template.read()
        for old, new in zip(self._old_strings, self._new_strings):
            self._content = self._content.replace(old, new)

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
