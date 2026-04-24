"""
Configure system authentication using the ``authselect`` tool.

This module provides a context manager, the ``Authselect`` class, which
automates system configuration for smart card authentication. It ensures
profiles are properly applied and restored to their original state.
"""


from os.path import exists

from traceback import format_exc

from SCAutolib import logger
from SCAutolib.utils import run
from SCAutolib.exceptions import SCAutolibFileNotExists


class Authselect:
    """
    Manage ``authselect`` configuration for smart card authentication.

    This class acts as a context manager to apply the ``sssd`` profile with
    specific features. It automatically creates a backup upon entry and
    restores the previous configuration upon exit.
    """

    backup_name = "SCAutolib_authselect_backup"

    def __init__(self, required: bool = False, lock_on_removal: bool = False,
                 mk_homedir: bool = False, sudo: bool = False,
                 gssapi: bool = False):
        """
        Initialize the ``Authselect`` object with specific profile features.

        By default, it enables the ``with-smartcard`` feature for the
        ``sssd`` profile and prepares the command options for execution.

        :param required: If ``True``, the ``with-smartcard-required`` option
                         will be added to the ``authselect`` profile.
        :type required: bool
        :param lock_on_removal: If ``True``, the
                                ``with-smartcard-lock-on-removal`` option will
                                be added to the ``authselect`` profile.
        :type lock_on_removal: bool
        :param mk_homedir: If ``True``, the ``with-mkhomedir``
                           option will be added to the ``authselect`` profile,
                           ensuring home directories are created on login.
        :type mk_homedir: bool
        :param sudo: If ``True``, the ``with-sudo`` option will
                     be added to the ``authselect`` profile, enabling sudo
                     integration.
        :type sudo: bool
        :param gssapi: If ``True``, the ``with-gssapi`` option will
                     be added to the ``authselect`` profile, enabling gssapi
                     integration.
        :type gssapi: bool
        :return: None
        :rtype: None
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
        if gssapi:
            self._options.append("with-gssapi")

    def _set(self):
        """
        Apply the SSSD profile with selected features.

        Uses the ``authselect select`` command to apply configurations
        and creates a system backup at the default authselect location.

        :return: None
        :rtype: None
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
        Restore the system to its original Authselect state.

        Attempts to revert changes using the backup file created during
        initialization.

        :return: None
        :rtype: None
        :raises SCAutolibFileNotExists: If the backup file expected for
                                        restoration does not exist.
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
            raise SCAutolibFileNotExists(
                "Backup file not found. _restore method was"
                "probably called in unexpected manner.")

    def __enter__(self) -> Authselect:
        """
        Enter the Authselect context manager.

        Applies the desired configuration immediately upon entering the
        ``with`` block.

        :return: The ``Authselect`` instance.
        :rtype: SCAutolib.models.authselect.Authselect
        """
        self._set()
        return self

    def __exit__(self, ext_type, ext_value, ext_traceback):
        """
        Exit the Authselect context manager.

        Automatically restores the original configuration. If an error
        occurred within the block, the details are logged before restoration.

        :param ext_type: The type of the exception that caused the context to
                         be exited, or ``None`` if no exception occurred.
        :type ext_type: type, optional
        :param ext_value: The exception instance that caused the context to be
                          exited, or ``None``.
        :type ext_value: Exception, optional
        :param ext_traceback: The traceback object associated with the
                              exception, or ``None``.
        :type ext_traceback: traceback, optional
        :return: None
        :rtype: None
        """
        if ext_type is not None:
            logger.error("Exception in authselect context")
            logger.error(format_exc())
        self._restore()
