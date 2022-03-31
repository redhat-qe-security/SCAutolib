from os.path import exists

from subprocess import check_output, PIPE
from traceback import format_exc

from SCAutolib import logger


class Authselect:
    backup_name = "tmp.backup"

    def __init__(self, required=False, lock_on_removal=False, mk_homedir=False):
        """
        Constructor for Authselect class. By default, only with-smartcard option
        is used. When setting the SSSD profile, also --force is used. Previous
        configuration would be store into backup file and restored on exiting
        the context manager.

        Args:
            required: specifies with-smartcard-required option
            lock_on_removal: specifies with-smartcard-lock-on-removal option
            mk_homedir: specifies with-mkhomedir option
        """
        self._options = ["with-smartcard"]
        self._required = required
        self._lock_on_removal = lock_on_removal
        self._mk_homedir = mk_homedir

    def _set(self):
        """
        Set authselect with SSSD profile and use given options. Options are
        passed into the constructor.
        """
        if self._required:
            self._options.append("with-smartcard-required")
        if self._lock_on_removal:
            self._options.append("with-smartcard-lock-on-removal")
        if self._mk_homedir:
            self._options.append("with-mkhomedir")
        args = ["authselect", "select", "sssd", *self._options,
                "--backup", self.backup_name, "--force"]

        check_output(args, stderr=PIPE, encoding="utf=8")
        logger.debug(f"SSSD is set to: {' '.join(args)}")
        logger.debug(f"Backup file: {self.backup_name}")

    def _reset(self):
        """
        Restore the previous configuration of authselect.
        """
        if exists(self.backup_name):
            check_output(["authselect", "backup-restore", self.backup_name,
                          "--debug"], stderr=PIPE, encoding="utf=8")

            check_output(["authselect", "backup-remove", self.backup_name,
                          "--debug"], stderr=PIPE, encoding="utf=8")
            logger.debug("Authselect backup file is restored")
        else:
            logger.warning("Authselect backup file does not exist, "
                           "skip configuration restore.")
            logger.warning("Manually disabling all features")
            for f in self._options:
                check_output(["authselect", "disable-feature", f])
                logger.debug(f"Authselect feature {f} is disabled")

    def __enter__(self):
        self._set()
        return self

    def __exit__(self, ext_type, ext_value, ext_traceback):
        if ext_type is not None:
            logger.error("Exception in authselect context")
            logger.error(format_exc())
        self._reset()
