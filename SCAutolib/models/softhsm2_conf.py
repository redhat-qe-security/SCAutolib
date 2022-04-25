"""
This module provide information and methods to create and modify
softhsm2.conf file. Following methods are implemented:

create: create content of internal file object representing softhsm2.conf
set:   set or modify content of internal file object representing softhsm2.conf
save:  save content of internal file object representing softhsm2.conf to
       softhsm2.conf file
clean: removes softhsm2.conf file
"""

from pathlib import Path

from SCAutolib import logger, TEMPLATES_DIR
from SCAutolib.models.file import File


class SoftHSM2Conf(File):
    """
    This class contains information and methods to handle softhsm2.conf file
    """
    _template = Path(TEMPLATES_DIR, "softhsm2.conf")
    _conf_file = None
    _content = None
    _card_dir = None

    def __init__(self, filepath: str, card_dir: str):
        """
        Init of SoftHSM2Conf

        :param filepath: path where config file should be saved
        :type filepath: str
        :param card_dir: parameter to be updated in config file
        :type card_dir: str
        """
        self._conf_file = Path(filepath)
        self._card_dir = card_dir

    def create(self):
        """
        Populate internal file object with content based on template.
        """
        with self._template.open('r') as template:
            content = template.readlines()
        self._content = []
        for line in content:
            modified = line.format(card_dir=self._card_dir)
            self._content.append(modified)

        logger.info(f"Creating content of {self._conf_file} based on {self._template}")
        logger.info(f" {self._conf_file}: directories.tokendir needs to be updated")

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
            config.writelines(self._content)
