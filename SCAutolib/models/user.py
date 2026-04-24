"""
Manage system and FreeIPA users for the SCAutolib framework.

This module defines the ``User`` and ``IPAUser`` classes, representing
local and FreeIPA users respectively. It handles user properties and
implements methods for adding and deleting users across platforms.
"""


import json
import pwd
import python_freeipa
from pathlib import Path, PosixPath

from SCAutolib import run, logger, LIB_DUMP_USERS
from SCAutolib.exceptions import SCAutolibException, SCAutolibIPAException, \
    SCAutolibUnknownType, SCAutolibFileNotExists
from SCAutolib.models.CA import IPAServerCA
from SCAutolib.enums import UserType


class User:
    """
    Represent a general local system user account.

    This class holds properties like username and password, providing
    methods to manage the user locally. Objects can be serialized to
    and loaded from JSON files for persistence.
    """

    username: str = None
    password: str = None
    dump_file: Path = None
    user_type: str = None

    def __init__(self, username: str, password: str):
        """
        Initialize a ``User`` object for a local system user.

        :param username: The username for the system user.
        :type username: str
        :param password: The password for the system user.
        :type password: str
        :return: None
        :rtype: None
        """
        self.username = username
        self.password = password
        self.user_type = UserType.local
        self.dump_file = LIB_DUMP_USERS.joinpath(f"{self.username}.json")

    def to_dict(self):
        """
        Convert the ``User`` attributes into a serializable dictionary.

        :return: A dictionary representation of the user object's attributes.
        :rtype: dict
        """
        # Retype patlib.Path object to str
        d = {k: str(v) if type(v) in (PosixPath, Path) else v
             for k, v in self.__dict__.items()}
        return d

    def add_user(self):
        """
        Add the user to the local system.

        Uses ``useradd`` and ``passwd --stdin``. It validates that the
        user does not already exist to prevent collisions.

        :return: None
        :rtype: None
        :raises SCAutolibException: If the user already exists on the system.
        """
        try:
            pwd.getpwnam(self.username)
            msg = f"User {self.username} already exists on this " \
                  f"machine. Username should be unique to avoid " \
                  f"future problems with collisions"
            logger.critical(msg)
            raise SCAutolibException(msg)
        except KeyError:
            logger.debug(f"Creating new user {self.username}")
            cmd = ['useradd', '-m', self.username]
            run(cmd, check=True)
            cmd = ["passwd", self.username, "--stdin"]
            run(cmd, input=self.password)
            logger.info(f"User {self.username} was added to the system")

    def delete_user(self):
        """
        Delete the local user and its associated dump file.

        Uses the ``userdel -f`` command to remove the account.

        :return: None
        :rtype: None
        """
        try:
            pwd.getpwnam(self.username)
            logger.info(f"Deleting the user {self.username}")
            run(['userdel', '-rf', self.username], check=True)
        except KeyError:
            logger.info(f"User {self.username} is not present on the system")

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

    @staticmethod
    def load(user_file: Path = None, username: str = None, **kwargs) -> User:
        """
        Reconstruct a user object from a JSON dump file.

        Determines whether to instantiate a ``User`` or ``IPAUser``
        based on the stored metadata.

        :param user_file: The ``pathlib.Path`` object pointing to the JSON file
                          from which to read the user's data.
        :type user_file: pathlib.Path
        :param kwargs: Additional keyword arguments that might be necessary to
                       initialize the user object, particularly for ``IPAUser``
                       which requires an ``ipa_server`` object.
        :param username: The username of the user to load.
        :type username: str
        :type kwargs: dict
        :return: An initialized ``User`` or ``IPAUser`` object loaded with data
                 from the JSON file.
        :rtype: SCAutolib.models.user.User or SCAutolib.models.user.IPAUser
        :raises SCAutolibFileNotExists: If user file is not found.
        :raises SCAutolibIPAException: if ``ipa_server`` is not provided for an
                                       IPA user.
        :raises SCAutolibUnknownType: If an unknown user type is encountered in
                                    the JSON data.
        """
        if username and not user_file:
            user_file = LIB_DUMP_USERS.joinpath(f"{username}.json")
            logger.debug(f"Loading user {username} from {user_file}")

        if not user_file.exists():
            raise SCAutolibFileNotExists(f"{user_file} does not exist")

        with user_file.open("r") as f:
            cnt = json.load(f)

        user = None
        if cnt["user_type"] == UserType.local:
            user = User(username=cnt["username"],
                        password=cnt["password"])

        elif cnt["user_type"] == UserType.ipa:
            if "ipa_server" not in kwargs:
                raise SCAutolibIPAException(
                    "IPA Server object was not provided. "
                    "Can't load IPA user.")

            user = IPAUser(ipa_server=kwargs["ipa_server"],
                           username=cnt["username"],
                           password=cnt["password"])

        else:
            raise SCAutolibUnknownType(
                f"Unknown user type: {cnt['user_type']}")

        logger.debug(f"User {user.__class__} is loaded: {user.__dict__}")

        return user


class IPAUser(User):
    """
    Represent an Identity Management (FreeIPA) user.

    Extends the base ``User`` class to manage users within an IPA
    environment via the ``python_freeipa`` library.
    """

    default_password = "redhat"

    def __init__(self, ipa_server: IPAServerCA, *args, **kwargs):
        """
        Initialize an ``IPAUser`` object.

        Requires a configured IPA client and an ``IPAServerCA`` object
        to communicate with the server.

        :param ipa_server: An ``IPAServerCA`` object that provides the
                           necessary IPA server hostname and ``ClientMeta``
                           object for interaction.
        :type ipa_server: SCAutolib.models.CA.IPAServerCA
        :param username: The username for the system user.
        :type username: str
        :param password: The password for the system user.
        :type password: str
        :return: None
        :rtype: None
        """
        super().__init__(*args, **kwargs)
        self.user_type = UserType.ipa
        self._meta_client = ipa_server.meta_client
        self._ipa_hostname = ipa_server.ipa_server_hostname

    def to_dict(self):
        """
        Convert attributes into a serializable dictionary.

        Removes non-serializable internal client attributes.

        :return: A dictionary representation of the IPA user object's
                 attributes.
        :rtype: dict
        """
        d = super().to_dict()
        d.pop("_meta_client")
        d.pop("_ipa_hostname")
        return d

    def add_user(self):
        """
        Add the user to the IPA server.

        Sets a temporary password and immediately updates it to prevent
        a forced password change on first login.

        :return: None
        :rtype: None
        :raises SCAutolibException: If the user already exists on the IPA
                                    server.
        """
        try:
            r = self._meta_client.user_add(self.username, self.username,
                                           self.username, self.username,
                                           o_userpassword=self.default_password)
            logger.debug(r)

            # To avoid forcing IPA server to change the password on first login
            # we changing it through the client
            client = python_freeipa.client.Client(self._ipa_hostname,
                                                  verify_ssl=False)
            client.change_password(self.username, self.password,
                                   self.default_password)
            logger.info(f"User {self.username} is added to the IPA server")
        except python_freeipa.exceptions.DuplicateEntry:
            msg = f"User {self.username} already exists on the " \
                  f"IPA server. Username should be unique to avoid " \
                  f"future problems with collisions"
            logger.critical(msg)
            raise SCAutolibException(msg)

    def delete_user(self):
        """
        Delete the user from the IPA server.

        If the user is not found, the error is caught and ignored.

        :return: None
        :rtype: None
        """
        try:
            r = self._meta_client.user_del(self.username)["result"]
            logger.info(f"User {self.username} is removed from the IPA server")
            logger.debug(r)
        except python_freeipa.exceptions.NotFound:
            pass
