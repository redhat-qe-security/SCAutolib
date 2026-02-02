"""
This module contains classes that represent and facilitate the manipulation of
various configuration files used within SCAutolib's operations.
It defines a generic ``File`` class for common file operations and specialized
subclasses like ``SSSDConf``, ``SoftHSM2Conf``, and ``OpensslCnf`` for managing
specific configuration file types.
These classes provide methods for creating, modifying (setting values), saving,
and cleaning (removing) configuration files, with some supporting backup and
restore functionalities.
"""


import os
from configparser import ConfigParser
from pathlib import Path
from shutil import copy2
from traceback import format_exc
from typing import Union
import json

from SCAutolib import logger, TEMPLATES_DIR, LIB_BACKUP, LIB_DUMP_CONFS, run
from SCAutolib.exceptions import SCAutolibFileExists, SCAutolibWrongConfig, \
    SCAutolibNoTemplate
from SCAutolib.utils import isDistro


class File:
    """
    This class serves as an interface and base implementation for generic
    operations on various configuration files.

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
        Initializes a ``File`` object, setting the path to the configuration
        file and an optional template file for content creation.

        :param filepath: The path to the configuration file that this object
                         will manage. Can be a string or a ``pathlib.Path``
                         object.
        :type filepath: Union[str, pathlib.Path]
        :param template: The path to a template file from which the
                         configuration file's content can be generated.
        :type template: pathlib.Path, optional
        :return: None
        :rtype: None
        """

        self._conf_file = Path(filepath)
        if template is not None:
            self._template = template

    @property
    def path(self):
        """
        Returns the ``pathlib.Path`` object representing the configuration file
        managed by this object.

        :return: The path of the configuration file.
        :rtype: pathlib.Path
        """

        return self._conf_file

    def create(self):
        """
        Populates the internal parser object  with content read from the
        template file. This method is typically called
        when the configuration file does not yet exist on the system.

        :return: None
        :rtype: None
        :raises SCAutolibFileExists: If the configuration file already exists
                                     on the file system.
        :raises SCAutolibNoTemplate: If no template file was provided during
                                     object initialization when ``create`` is
                                     called.
        """

        if self._conf_file.exists():
            logger.warning(f"Create error: {self._conf_file} already exists.")
            raise SCAutolibFileExists(f'{self._conf_file} already exists')
        else:
            self._default_parser = ConfigParser()
            self._default_parser.optionxform = str
            if self._template is None:
                raise SCAutolibNoTemplate("Template file was not provided.")
            with self._template.open() as t:
                self._default_parser.read_file(t)

    def remove(self):
        """
        Removes the configuration file from the file system if it exists.

        :return: None
        :rtype: None
        """

        if self._conf_file.exists():
            self._conf_file.unlink()
            logger.debug(
                f"Removed file {self._conf_file}."
            )

    def exists(self):
        """
        Checks if the configuration file managed by this object exists on the
        file system.

        :return: ``True`` if the file exists; ``False`` otherwise.
        :rtype: bool
        """

        return self._conf_file.exists()

    def set(self, key: str, value: Union[int, str, bool], section: str = None,
            separator: str = "="):
        """
        Modifies a specific key-value pair within the configuration file.
        Modification is made through the
        ConfigParser object if it is defined. If not, then key value pair
        would be written to the file through normal :code:`write()` method with
        composed string in the following form :code:`<key><separator><value>`

        :param key: The key whose value will be updated.
        :type key: str
        :param value: The new value to be stored for the specified key.
        :type value: Union[int, str, bool]
        :param section: The name of the section within the config file where
                        the key is located. If ``None``, the file is treated as
                        a simple key-value file without sections.
        :type section: str, optional
        :param separator: The character used to separate the key and value in
                          simple (non-``ConfigParser``) config files.
                          Defaults to ``=``. Spaces around the key should be
                          included as part of the separator if needed.
        :type separator: str
        :return: None
        :rtype: None
        :raises ValueError: If a line in a simple config file is not in an
                            expected ``key=value`` format.

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
        ``ConfigParser``, then this object would be used to look for the
        key.

        :param key: The key whose value is to be retrieved.
        :type key: str
        :param section: The name of the section where the key is expected to be
                        found. If ``None``, the file is parsed line by line.
        :type section: str, optional
        :param separator: The character used to split lines into key-value
                          pairs for simple (non-``ConfigParser``) files.
                          Defaults to ``=``.
        :type separator: str
        :return: The string value associated with the key.
        :rtype: str
        :raises SCAutolibWrongConfig: If the section or key is not found in the
                                      file.
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

            raise SCAutolibWrongConfig(f"Key '{key}' doesn't present in the "
                                       f"file {self._conf_file}")
        elif self._default_parser is None:
            self._default_parser = ConfigParser()
            self._default_parser.optionxform = str
            with self._conf_file.open() as config:
                self._default_parser.read_file(config)

        try:
            value = self._default_parser[section][key]
        except KeyError as e:
            raise SCAutolibWrongConfig(str(e))

        return value

    def save(self):
        """
        Saves the current content of the configuration file, as stored in
        the internal parser objects to the file system.

        :return: None
        :rtype: None
        """

        if self._simple_content is None:
            with self._conf_file.open("w") as config:
                self._default_parser.write(config)
        else:
            with self._conf_file.open("w") as config:
                config.writelines(self._simple_content)

    def backup(self, name: str = None):
        """
        Saves a copy of the original configuration file to a designated backup
        directory. The backup file's name can be customized
        or defaults to ``<filename>.<extension>.backup``.

        :param name: An optional custom file name to be used for the backup
                     file.
        :type name: str, optional
        :return: The ``pathlib.Path`` object indicating where the backup file
                 is stored.
        :rtype: pathlib.Path
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
        Restores the configuration file by copying a previously created backup
        file back to the original file's location.
        After restoration, the backup file is removed.

        :param name: The custom name of the backup file to restore from. If
                     ``None``, it defaults to
                     ``<filename>.<extension>.backup``.
        :type name: str, optional
        :return: None
        :rtype: None
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
        else:
            logger.debug(
                f"File {self._conf_file} was not backed up. Nothing to do."
            )


class SSSDConf(File):
    """
    This class manages the ``/etc/sssd/sssd.conf`` file, providing methods to
    create, modify, save, and restore its content.

    It is implemented as a singleton, ensuring a single representation of the
    SSSD configuration during runtime.

    It also acts as a context manager to temporarily apply and then revert SSSD
    configuration changes.

    Intended use is to create/update and save config file in first runtime
    and load content of config file to internal parser object in following
    runtimes.
    """
    __instance = None
    _conf_file = Path("/etc/sssd/sssd.conf")
    _backup_original = None
    _backup_default = LIB_BACKUP.joinpath('default-sssd.conf')
    _backup_current_cont = None
    _before_last_change_cont = None
    _changed = False

    dump_file: Path = LIB_DUMP_CONFS.joinpath("SSSDConf.json")

    def __new__(cls):
        """
        Ensures that only a single instance of ``SSSDConf`` is created
        (singleton pattern).

        :return: The singleton instance of ``SSSDConf``.
        :rtype: SCAutolib.models.file.SSSDConf
        """

        if cls.__instance is None:
            cls.__instance = super(SSSDConf, cls).__new__(cls)
            cls.__instance.__initialized = False
        return cls.__instance

    def __init__(self):
        """
        Initializes the ``SSSDConf`` instance, setting up its configuration
        file paths and internal parsers. It loads default
        content and checks for existing backup files to maintain state across
        runs.
        """

        if self.__initialized:
            return
        self.__initialized = True

        if isDistro(['rhel', 'centos'], version='<=9') \
                or isDistro(['fedora'], version='<39'):
            self._template = TEMPLATES_DIR.joinpath("sssd.conf-8or9")
        else:
            self._template = TEMPLATES_DIR.joinpath("sssd.conf-10")

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
        """
        Allows the ``SSSDConf`` object to be called directly, similar to a
        context manager for setting and saving a single configuration change.
        It updates the SSSD configuration, saves it,
        and then restarts the SSSD service.

        :param key: The key from a section of the config file to be updated.
        :type key: str
        :param value: The new value to be stored in the specified section and
                      key.
        :type value: Union[int, str, bool]
        :param section: The section of the config file to be created or
                        updated.
        :type section: str, optional
        :return: The ``SSSDConf`` instance itself.
        :rtype: SCAutolib.models.file.SSSDConf
        """

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
        """
        Enters the context manager for ``SSSDConf``.
        It saves the current content of ``sssd.conf`` to an internal backup
        to enable restoration upon exiting the context.

        :return: The ``SSSDConf`` instance.
        :rtype: SCAutolib.models.file.SSSDConf
        """

        # Check if we changed the file or not and save version before context
        # manager was called
        if self._before_last_change_cont:
            self._backup_current_cont = self._before_last_change_cont
        else:
            with self._conf_file.open() as config:
                self._backup_current_cont = config.read()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exits the context manager for ``SSSDConf``.
        If any changes were made within the context, it restores ``sssd.conf``
        to the version saved upon entry.
        It then restarts the SSSD service and logs any exceptions that occurred
        within the context.

        :param exc_type: The type of the exception that caused the context to be
                         exited, or ``None`` if no exception occurred.
        :param exc_value: The exception instance that caused the context to be
                          exited, or ``None``.
        :param traceback: The traceback object associated with the exception,
                          or ``None``.
        :return: None
        :rtype: None
        """

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
        Populates the internal parser object with content from the existing
        ``sssd.conf`` file, then updates it with values from a predefined
        template. It also backs up the original ``sssd.conf`` file.
        This method handles cases where the file might not initially exist.

        :return: None
        :rtype: None
        :raises SCAutolibFileExists: If internal backup files already exist,
                                     suggesting ``create`` was executed
                                     multiple times.
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
        Modifies or adds a key-value pair within the SSSD configuration file
        represented by the internal ``ConfigParser`` object.

        :param key: The key from a section of the config file to be updated.
        :type key: str
        :param value: The new value to be stored in the specified section and
                      key.
        :type value: Union[int, str, bool]
        :param section: The section of the config file to be created or
                        updated. This parameter is required for SSSDConf
                        operations.
        :type section: str
        :return: None
        :rtype: None
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
        Saves the current content of the SSSD configuration file, which is
        managed by the internal parser objects.
        The file permissions are set to ``0o600``.

        .. note: SSSD service restart is caller's responsibility.

        :return: None
        :rtype: None
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
        Restores the ``sssd.conf`` file to its original version before any
        modifications by SCAutolib. If a backup exists, it is copied back;
        otherwise, the file is simply removed if it was created by SCAutolib.
        It also removes internal backup files.

        .. note: SSSD service restart is caller's responsibility.

        :return: None
        :rtype: None
        """

        if self._backup_original and self._backup_original.exists():
            with self._backup_original.open() as original, \
                    self._conf_file.open("w") as config:
                config.write(original.read())
            self._backup_original.unlink()
        else:
            self.remove()

        if self._backup_default.exists():
            self._backup_default.unlink()

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

        logger.info("Restored sssd.conf to the original version")
        self._changed = False

    def update_default_content(self):
        """
        Populates the internal parser with the content from the
        current ``sssd.conf`` file on the system. It then
        backs up this current state.

        :return: None
        :rtype: None
        """

        self._default_parser = ConfigParser()
        self._default_parser.optionxform = str
        with self._conf_file.open() as config:
            self._default_parser.read_file(config)
        logger.info(f"Backing up {self._conf_file} as {self._backup_default}")
        copy2(self._conf_file, self._backup_default)

    def check_backups(self):
        """
        Checks if internal backup files for ``sssd.conf`` already exist.
        If any backup file is found, it raises an exception, suggesting that
        the ``create`` method might have been executed multiple times
        unintentionally.

        :return: None
        :rtype: None
        :raises SCAutolibFileExists: If an internal backup file already exists.
        """

        backup_files = (self._backup_default, self._backup_original)
        for file in backup_files:
            if file.exists():
                logger.error(f"Backup of {file} already exists")
                logger.error("This suggest that create method was already "
                             "executed. Create method should not be executed "
                             "multiple times")
                raise SCAutolibFileExists(f'{file} file exists')


class SoftHSM2Conf(File):
    """
    This class manages the ``softhsm2.conf`` file, providing methods to
    create its content based on a template and save it.
    It's specifically designed for SoftHSM2 configuration, which does not
    use traditional sections.
    """
    _template = Path(TEMPLATES_DIR, "softhsm2.conf")
    _conf_file = None
    _content = None
    _card_dir = None

    def __init__(self, filepath: Union[str, Path], card_dir: Union[str, Path]):
        """
        Initializes a ``SoftHSM2Conf`` object, setting the path for the
        configuration file and the card directory, which is used to format
        the template content.

        :param filepath: The path where the ``softhsm2.conf`` file should be
                         saved.
        :type filepath: Union[str, pathlib.Path]
        :param card_dir: The path to the card's directory, which will be
                         inserted into the ``softhsm2.conf`` template
                         (e.g., for ``directories.tokendir``).
        :type card_dir: Union[str, pathlib.Path]
        :return: None
        :rtype: None
        """

        self._conf_file = filepath if isinstance(filepath, Path) else \
            Path(filepath)
        self._card_dir = card_dir if isinstance(card_dir, Path) else \
            Path(card_dir)

    def create(self):
        """
        Populates the internal content attribute by reading the
        ``softhsm2.conf`` template and formatting it with the provided
        ``card_dir``.

        :return: None
        :rtype: None
        """

        with self._template.open('r') as template:
            self._content = template.read().format(card_dir=self._card_dir)

        logger.info(f"Creating content of {self._conf_file} "
                    f"based on {self._template}")

    def set(self, *args):
        """
        This method is not implemented for ``SoftHSM2Conf`` as ``softhsm2.conf``
        does not use sections in a way that ``File.set`` can handle.

        :param args: Positional arguments (not used).
        :type args: tuple
        :return: None
        :rtype: None
        :raises NotImplementedError: Always raised when this method is called.
        """

        logger.warning("softhsm2.conf does not contain sections.")
        raise NotImplementedError("softHSM2conf.set method not implemented")

    def save(self):
        """
        Saves the content stored in the internal content attribute to the
        ``softhsm2.conf`` file on the file system.

        :return: None
        :rtype: None
        """

        with self._conf_file.open("w") as config:
            config.write(self._content)
        logger.debug(f"Config file {self._conf_file} is created")


class OpensslCnf(File):
    """
    This class manages OpenSSL configuration files (``.cnf`` files), providing
    methods to create and modify their content. It supports
    different types of configuration files (e.g., for CAs, for users) by
    utilizing specific templates and performing string replacements.
    """
    _template = None
    _conf_file = None
    _content = None
    _old_string = None
    _new_string = None

    # openssl configuration content depends substantially on its purpose and
    # separate templates are needed for specific config files types. mapping:
    types = {
        "CA": {"template": Path(TEMPLATES_DIR, 'ca.cnf'),
               "replace": ["{ROOT_DIR}"]},
        "user": {"template": Path(TEMPLATES_DIR, 'user.cnf'),
                 "replace": ["{user}", "{cn}"]}
    }

    def __init__(self, filepath: Union[str, Path], conf_type: str,
                 replace: Union[str, list]):
        """
        Initializes an ``OpensslCnf`` object, setting up the paths for the
        configuration file and its corresponding template.
        It also prepares the strings that will be used for replacement within
        the template based on the `conf_type`.

        :param filepath: The path where the OpenSSL configuration file will be
                         saved.
        :type filepath: Union[str, pathlib.Path]
        :param conf_type: An identifier string indicating the type of
                          configuration file (e.g., `"CA"` or `"user"`), which
                          determines the template and replacement patterns.
        :type conf_type: str
        :param replace: A string or list of strings that will replace specific
                        placeholder strings (e.g., `"{ROOT_DIR}"`, `"{user}"`)
                        from the template.
        :type replace: Union[str, list]
        :return: None
        :rtype: None
        """

        self._conf_file = Path(filepath)
        self._template = Path(self.types[conf_type]["template"])
        self._old_strings = self.types[conf_type]["replace"]
        if isinstance(replace, str):
            replace = [replace]
        self._new_strings = replace

    def create(self):
        """
        Populates the internal content attribute by reading the template
        file and performing string replacements based on the initialized
        old and new strings. This prepares the
        content to be written to the actual configuration file.

        :return: None
        :rtype: None
        """

        with self._template.open('r') as template:
            self._content = template.read()
        for old, new in zip(self._old_strings, self._new_strings):
            self._content = self._content.replace(old, new)

    def save(self):
        """
        Saves the content stored in the internal content attribute (or
        parser if ``set`` was used) to the OpenSSL configuration file on the
        file system.

        :return: None
        :rtype: None
        """

        with self._conf_file.open("w") as config:
            if self._default_parser is None:
                config.write(self._content)
            else:
                # in case set method was used
                self._default_parser.write(config)
