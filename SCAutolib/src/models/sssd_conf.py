from .file import File
from pathlib import Path
from configparser import ConfigParser
from SCAutolib import logger


class SSSDConf(File):
    _template = Path()
    _sssd_conf_path = Path("/etc/sssd/sssd.conf")
    _parser = ConfigParser()
    # Needed to avoid parsing problems on inserting some 'specific' value,
    # that cause an exception with default method
    _parser.optionxform = str
    with _sssd_conf_path.open() as f:
        _parser.read_file(f)

    @classmethod
    def set(cls, key: str, value: str, section: str = None):
        """
        Set value in SSSD config file. Parameter 'section' has to be specified.
        """
        previous = cls._parser.get(section, key, fallback=None)
        if previous is None:
            previous = "Not set"
        cls._parser.set(section, key, value)

        logger.info(f"Value is change in {cls._sssd_conf_path}")
        logger.debug(f"Old value in section [{section}] {key}={previous}")
        logger.debug(f"New value in section [{section}] {key}={value}")

    @classmethod
    def save(cls):
        with cls._sssd_conf_path.open("w") as f:
            cls._parser.write(f)
