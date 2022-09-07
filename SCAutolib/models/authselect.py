"""
This module provides methods allowing to configure system for smart-card
authentication implemented as context manager. It calls authselect tool (see man
authselect(8)) and applies sssd profile with selected 'Authselect profile
features' (see man authselect-migration(7)).
"""
from os.path import exists

from traceback import format_exc

from SCAutolib import LIB_BACKUP
from SCAutolib import logger
from SCAutolib.utils import run


class Authselect:
    backup_name = LIB_BACKUP.joinpath("SCAutolib_authselect_backup")

    def __init__(self, required=False, lock_on_removal=False,
                 mk_homedir=False, sudo=False):
        """
        Constructor for Authselect class. Only 'with-smartcard' feature of sssd
        profile is set by default and --force option is used if the sssd profile
        is modified. Previous configuration is backed up and restored on exiting
        context manager.

        :param required: specifies with-smartcard-required option
        :type required: bool
        :param lock_on_removal: specifies with-smartcard-lock-on-removal option
        :type lock_on_removal: bool
        :param mk_homedir: specifies with-mkhomedir option
        :type mk_homedir: bool
        """

        self._options = ["with-smartcard"]
        if required:
            self._options.append("with-smartcard-required")
        if lock_on_removal:
            self._options.append("with-smartcard-lock-on-removal")
        if mk_homedir:
            self._options.append("with-mkhomedir")
        if sudo:
            self._options.append("with-sudo")

    def _set(self):
        """
        Set authselect with SSSD profile and set selected Authselect profile
        features. Features are passed into the constructor.
        """

        # compose and run Authselect command
        cmd = ["authselect", "select", "sssd", *self._options,
               "--backup", self.backup_name, "--force"]
        run(cmd)

        # get modified setup and log it
        logger.debug("Current Authselect setting is:")
        run(["authselect", "current"], return_code=[0, 2])

        logger.debug(f"Original Authselect configuration was backed up with "
                     f"authselect to default location as : "
                     f"{str(self.backup_name)}")
        logger.debug("Default location is: /var/lib/authselect/backups/")

    def _restore(self):
        """
        Restore the previous configuration of authselect.
        """
        if exists(f"/var/lib/authselect/backups/{self.backup_name}"):
            cmd = ["authselect", "backup-restore", self.backup_name, "--debug"]
            run(cmd)
            logger.debug("Authselect configuration is restored to:")
            run(["authselect", "current"], return_code=[0, 2])
        else:
            # as _set and _restore should be used in context manager defined in
            # this class, it should not happen that backup does not exist except
            # something failed, or it's misused
            raise FileNotFoundError("Backup file not found. _restore method was"
                                    "probably called in unexpected manner.")

    def __enter__(self):
        self._set()
        return self

    def __exit__(self, ext_type, ext_value, ext_traceback):
        if ext_type is not None:
            logger.error("Exception in authselect context")
            logger.error(format_exc())
        self._restore()
