"""
Represent and manipulate configuration files for SCAutolib.

This module defines a generic ``File`` class for common operations and
specialized subclasses like ``SSSDConf``, ``SoftHSM2Conf``, and ``OpensslCnf``
for managing specific configuration formats. It provides methods for
creating, modifying, saving, and restoring files.
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
    Interface and base implementation for configuration file operations.

    Supports creation from templates, key-value modification, saving, and
    removal. It handles both ConfigParser-compatible files (with sections)
    and simple flat key-value files.
    """

    _conf_file = None
    _template = None
    _default_parser = None
    _simple_content = None

    def __init__(self, filepath: Union[str, Path], template: Path = None):
        """
        Initialize a ``File`` object with a path and optional template.

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
    def path(self) -> Path:
        """
        Return the path of the configuration file.

        :return: The path of the configuration file.
        :rtype: pathlib.Path
        """
        return self._conf_file

    def create(self):
        """
        Populate the internal parser with content from the template.

        This is used when the configuration file does not yet exist on
        the system.

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
        Remove the configuration file from the system if it exists.

        :return: None
        :rtype: None
        """
        if self._conf_file.exists():
            self._conf_file.unlink()
            logger.debug(
                f"Removed file {self._conf_file}."
            )

    def exists(self) -> bool:
        """
        Check if the configuration file exists on the system.

        :return: ``True`` if the file exists; ``False`` otherwise.
        :rtype: bool
        """
        return self._conf_file.exists()

    def set(
        self, key: str, value: Union[int, str, bool], section: str = None,
        separator: str = "="
    ):
        """
        Modify a specific key-value pair within the configuration.

        If a section is provided, ConfigParser is used. Otherwise, it
        updates the file as a flat key-value pair string.

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
                except ValueError as e:
                    raise SCAutolibWrongConfig(
                        f"unexpected format of line: {line}") from e
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

    def get(self, key, section: str = None, separator: str = "=") -> str:
        """
        Retrieve the value associated with a key.

        If no section is provided, it performs a line-by-line search.

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
            raise SCAutolibWrongConfig() from e

        return value

    def save(self):
        """
        Save the current content to the file system.

        :return: None
        :rtype: None
        """
        if self._simple_content is None:
            with self._conf_file.open("w") as config:
                self._default_parser.write(config)
        else:
            with self._conf_file.open("w") as config:
                config.writelines(self._simple_content)

    def backup(self, name: str = None) -> Path:
        """
        Save a copy of the configuration to the backup directory.

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
        Restore the configuration from a previously created backup.

        The backup file is removed after successful restoration.

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
    Manage the ``/etc/sssd/sssd.conf`` file as a singleton.

    Provides methods to modify and restore SSSD settings. It acts as a
    context manager to temporarily apply and then revert changes.
    """

    __instance = None
    _conf_file = Path("/etc/sssd/sssd.conf")
    _backup_original = None
    _backup_default = LIB_BACKUP.joinpath('default-sssd.conf')
    _backup_current_cont = None
    _before_last_change_cont = None
    _changed = False

    dump_file: Path = LIB_DUMP_CONFS.joinpath("SSSDConf.json")

    def __new__(cls) -> SSSDConf:
        """
        Ensure only a single instance of SSSDConf exists.

        :return: The singleton instance of ``SSSDConf``.
        :rtype: SCAutolib.models.file.SSSDConf
        """
        if cls.__instance is None:
            cls.__instance = super(SSSDConf, cls).__new__(cls)
            cls.__instance.__initialized = False
        return cls.__instance

    def __init__(self):
        """
        Initialize the SSSDConf singleton instance.

        Sets up configuration file paths and internal parsers. It loads
        default content and checks for existing backup files to maintain
        state across runs.
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

    def __call__(
        self, key: str, value: Union[int, str, bool], section: str = None
    ) -> SSSDConf:
        """
        Apply a configuration change and restart SSSD.

        Used to facilitate single-change updates via the context manager
        pattern.

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

    def __enter__(self) -> SSSDConf:
        """
        Enter the context manager and capture the current state.

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
        Exit the context manager and revert any changes if necessary.

        Restores the file and restarts the SSSD service.

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
        Initialize sssd.conf from an existing file or template.

        Backs up the original file if it exists.

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

            with self._conf_file.open("w") as conf:
                self._default_parser.write(conf)

        with self.dump_file.open("w") as f:
            json.dump({
                "_backup_original": str(self._backup_original)
            }, f)

    def set(self, key: str, value: Union[int, str, bool], section: str = None):
        """
        Update a key-value pair in the SSSD configuration.

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
        Write the current SSSD configuration to the file.

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
        Restore sssd.conf to its original state and cleanup backups.

        .. note: SSSD service restart is caller's responsibility.

        :return: None
        :rtype: None
        """
        if self._backup_original and self._backup_original.exists():
            with self._backup_original.open() as original, \
                    self._conf_file.open("w") as config:
                config.write(original.read())
            self._backup_original.unlink()
            logger.info("Restored sssd.conf to the original version")
        else:
            self.remove()
            logger.info("No sssd.conf original version found. Removed.")

        if self._backup_default.exists():
            self._backup_default.unlink()

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

        self._changed = False

    def update_default_content(self):
        """
        Update default content from the current sssd.conf.

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
        Verify that internal backup files do not already exist.

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

    def update_matchrule(self, cardholder: str, CN: str):
        """
        Link a user to a smart card via SSSD matchrule.

        :param cardholder: The user name of the card holder.
        :type cardholder: str
        :param CN: The Common Name of the card.
        :type CN: str
        :return: None
        :rtype: None
        """
        self.set(section=f"certmap/shadowutils/{cardholder}",
                 key="matchrule",
                 value=f"<SUBJECT>.*CN={CN}.*")
        self.save()
        run(["sss_cache", "-E"])
        run(["systemctl", "restart", "sssd"])


class SoftHSM2Conf(File):
    """
    Manage the ``softhsm2.conf`` configuration file.

    Formatted for SoftHSM2 which does not use sections.
    """

    _template = Path(TEMPLATES_DIR, "softhsm2.conf")
    _conf_file = None
    _content = None
    _card_dir = None

    def __init__(self, filepath: Union[str, Path], card_dir: Union[str, Path]):
        """
        Initialize SoftHSM2Conf with file paths.

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
        Create content based on the SoftHSM2 template.

        :return: None
        :rtype: None
        """
        with self._template.open('r') as template:
            self._content = template.read().format(card_dir=self._card_dir)

        logger.info(f"Creating content of {self._conf_file} "
                    f"based on {self._template}")

    def set(self, *args):
        """
        Set method of SoftHSM2 is not implemented yet.

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
        Save the SoftHSM2 configuration file to the file system.

        :return: None
        :rtype: None
        """
        with self._conf_file.open("w") as config:
            config.write(self._content)
        logger.debug(f"Config file {self._conf_file} is created")


class OpensslCnf(File):
    """
    Manage OpenSSL configuration files (``.cnf``).

    Supports specific templates for CAs and users through placeholder
    replacements.
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

    def __init__(
        self, filepath: Union[str, Path], conf_type: str,
        replace: Union[str, list]
    ):
        """
        Initialize OpensslCnf with paths and replacement logic.

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
        Generate content by applying string replacements to the template.

        :return: None
        :rtype: None
        """
        with self._template.open('r') as template:
            self._content = template.read()
        for old, new in zip(self._old_strings, self._new_strings):
            self._content = self._content.replace(old, new)

    def save(self):
        """
        Save OpenSSL configuration file to the file system.

        :return: None
        :rtype: None
        """
        with self._conf_file.open("w") as config:
            if self._default_parser is None:
                config.write(self._content)
            else:
                # in case set method was used
                self._default_parser.write(config)
