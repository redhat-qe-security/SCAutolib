"""
This module defines the ``User`` and ``IPAUser`` classes, which are designed to
represent and manage system and FreeIPA users within the SCAutolib framework.

These classes encapsulate user properties
like username and password, and implement methods for common user management
operations such as adding and deleting users from either the local system
or a specified IPA server.
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
    Represents a general system user, typically a local user account on the
    machine where SCAutolib is running.
    It holds user properties like username and password, and provides methods
    to manage the user's presence on the local system.
    User objects can be serialized to and loaded from JSON dump files for
    persistence across SCAutolib runs.
    """
    username: str = None
    password: str = None
    dump_file: Path = None
    user_type: str = None

    def __init__(self, username: str, password: str):
        """
        Initializes a ``User`` object for a local system user.

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
        Converts the ``User`` object's attributes into a dictionary suitable
        for JSON serialization.

        :return: A dictionary representation of the user object's attributes.
        :rtype: dict
        """

        # Retype patlib.Path object to str
        d = {k: str(v) if type(v) in (PosixPath, Path) else v
             for k, v in self.__dict__.items()}
        return d

    def add_user(self):
        """
        Adds the user to the local system using the ``useradd`` system
        management command and sets their password via ``passwd --stdin``.
        It checks if the user already exists to prevent collisions.

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
        Deletes the local user from the system using the ``userdel -f``
        command.
        It also removes the corresponding JSON dump file for the user.

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
    def load(user_file: Path = None, username: str = None, **kwargs):
        """
        Loads user data from a specified JSON file and reconstructs the
        corresponding ``User`` or ``IPAUser`` object.
        It determines the correct class to instantiate based on the
        ``user_type`` field in the JSON content.

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
    Represents an IPA (Identity Management for Linux) user.
    This class extends the base ``User`` class to include specific
    functionalities for managing users within an IPA server environment,
    primarily through the ``python_freeipa`` library.
    """
    default_password = "redhat"

    def __init__(self, ipa_server: IPAServerCA, *args, **kwargs):
        """
        Initializes an ``IPAUser`` object.
        IPA client should be configured first before creating an IPA user
        through this class.
        It requires an ``IPAServerCA`` object to facilitate communication with
        the IPA server and inherits user attributes from the base ``User``
        class.

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
        Converts the ``IPAUser`` object's attributes into a dictionary for
        JSON serialization. It calls the base ``User.to_dict()``
        method and then removes internal ``_meta_client`` and ``_ipa_hostname``
        attributes, which are not directly serializable.

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
        Adds the IPA user to the IPA server using the ``python_freeipa`` client.
        It sets a default password and then changes it to the specified
        password to avoid requiring a password change on first login.

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
        Deletes the IPA user from the IPA server using the ``python_freeipa``
        client. If the user is not found on the server,
        the operation is silently ignored.

        :return: None
        :rtype: None
        """
        try:
            r = self._meta_client.user_del(self.username)["result"]
            logger.info(f"User {self.username} is removed from the IPA server")
            logger.debug(r)
        except python_freeipa.exceptions.NotFound:
            pass
