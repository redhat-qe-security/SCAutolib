from configparser import ConfigParser
from pathlib import Path
from shutil import copy2
from SCAutolib import logger, TEMPLATES_DIR, LIB_BACKUP
from .file import File


class SSSDConf(File):
    _template = Path(TEMPLATES_DIR, "sssd.conf")
    _sssd_conf_path = Path("/etc/sssd/sssd.conf")
    _backup_original = Path(LIB_BACKUP, 'original_sssd.conf')
    _backup_default = Path(LIB_BACKUP, 'default_sssd.conf')

    @classmethod
    def create(cls):
        """
        Creates sssd.conf file if not present in the system or update existing
        sssd.conf file with values from template file provided by this package
        and backup original file.
        """
        parser = ConfigParser()
        # avoid problems with inserting some 'specific' values
        parser.optionxform = str

        # this method should be executed only once to create default config
        # existing backup files indicates that this method was already executed
        # in such case exception should be raised
        if cls._backup_original.exists():
            logger.error("Backup of original sssd.conf already exists")
            raise FileExistsError('backup file exists')
        if cls._backup_default.exists():
            logger.error("Default sssd.conf backup already exists")
            raise FileExistsError('backup file exists')

        try:
            with cls._sssd_conf_path.open() as config:
                parser.read_file(config)
            copy2(cls._sssd_conf_path, cls._backup_original)        # BACKUP
        except FileNotFoundError:
            logger.warning(f"sssd.conf not present in {cls._sssd_conf_path}")
            logger.warning("Creating sssd.conf based on the template")
        with cls._template.open() as template:
            logger.info("Updating sssd.conf with values from the template")
            parser.read_file(template)
        with cls._sssd_conf_path.open("w") as config:
            parser.write(config)
        copy2(cls._sssd_conf_path, cls._backup_default)

    @classmethod
    def set(cls, key: str, value: str, section: str = None):
        """
        Set value in SSSD config file. Parameter 'section' has to be specified.
        """
        parser = ConfigParser()
        parser.optionxform = str

        try:
            with cls._sssd_conf_path.open() as config:
                parser.read_file(config)
        except FileNotFoundError:
            logger.error(f"sssd.conf not present in {cls._sssd_conf_path}")
            raise

        if not parser.has_section(section):
            logger.warning(f"Section {section} not present in sssd.conf")
            logger.warning(f"Adding section {section} to sssd.conf")
            parser.add_section(section)

        previous = parser.get(section, key, fallback="Not set")

        parser.set(section, key, value)
        logger.info(f"Value is change in {cls._sssd_conf_path}")
        logger.debug(f"Old value in section [{section}] {key}={previous}")
        logger.debug(f"New value in section [{section}] {key}={value}")

        with cls._sssd_conf_path.open("w") as config:
            parser.write(config)

    @classmethod
    def clean(cls):
        """
        Removes sssd.conf file in case it was created by this package or
        restore original sssd.conf in case the file was modified.
        """
        if cls._backup_original.exists():
            copy2(cls._backup_original, cls._sssd_conf_path)
        else:
            cls._sssd_conf_path.unlink()
