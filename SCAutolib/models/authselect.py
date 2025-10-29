"""
This module provides methods allowing to configure the system for smart-card
authentication using the ``authselect`` tool.

It is implemented as a context manager (``Authselect`` class), which
ensures that system configurations are properly set up upon entry and
restored to their original state upon exit.
The module interacts with ``authselect(8)`` to apply the ``sssd`` profile
with specified features (for more information see manual page for
``authselect(8)``).
"""


from os.path import exists

from traceback import format_exc

from SCAutolib import logger
from SCAutolib.utils import run
from SCAutolib.exceptions import SCAutolibFileNotExists


class Authselect:
    """
    Manages the ``authselect`` configuration of the system for smart card
    authentication. This class is designed to be
    used as a context manager, ensuring that any changes made to ``authselect``
    profiles are automatically backed up and restored to their previous state
    upon exiting the context. It configures the
    ``sssd`` profile with specific features like ``with-smartcard``.
    """
    backup_name = "SCAutolib_authselect_backup"

    def __init__(self, required: bool = False, lock_on_removal: bool = False,
                 mk_homedir: bool = False, sudo: bool = False):
        """
        Initializes the ``Authselect`` object with desired ``authselect``
        profile features. By default, it sets the ``with-smartcard``
        feature for the ``sssd`` profile and uses the ``--force`` option to
        apply changes.

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

    def _set(self):
        """
        Applies the SSSD profile with the selected Authselect profile
        features using the ``authselect`` command. It also backs
        up the previous Authselect configuration to a default location.

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
        Restores the Authselect configuration to the state it was in before
        the Authselect class context manager applied its changes.
        It attempts to restore from the backup file created during ``_set()``.

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

    def __enter__(self):
        """
        Enters the Authselect calls context manager.
        This method calls ``_set()`` to apply the desired Authselect
        configuration and returns the instance itself, allowing for ``with``
        statement usage.

        :return: The ``Authselect`` instance.
        :rtype: SCAutolib.models.authselect.Authselect
        """

        self._set()
        return self

    def __exit__(self, ext_type, ext_value, ext_traceback):
        """
        Exits the Authselect class context manager.
        This method is called automatically when exiting a ``with`` statement.
        It attempts to restore the Authselect configuration to its original
        state by calling ``_restore()``. If an exception occurred
        within the context, it logs the exception details.

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
