"""
This module defines the User and IPAUser classes which can be used
to represent system and IPA users.

The classes contain the usual properties that defines a user, like username,
password, etc.

The classes implement add_user and delete_user methods which can be used to
create or remove a specified user in the system or in the specified IPA server.
"""
import json
import pwd
import python_freeipa
from pathlib import Path, PosixPath

from SCAutolib import run, logger, LIB_DUMP_USERS
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models.CA import IPAServerCA
from SCAutolib.enums import UserType


class User:
    """
    User represents general system user.
    """
    username: str = None
    password: str = None
    dump_file: Path = None
    user_type: str = None

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.user_type = UserType.local
        self.dump_file = LIB_DUMP_USERS.joinpath(f"{self.username}.json")

    def to_dict(self):
        # Retype patlib.Path object to str
        d = {k: str(v) if type(v) in (PosixPath, Path) else v
             for k, v in self.__dict__.items()}
        return d

    @staticmethod
    def load(json_file, **kwargs):
        """
        Load values from user's JSON file to corresponding user object.

        :param json_file: path to JSON file to read from
        :type json_file: pathlib.Path
        :param kwargs: dictionary of additional values needed to initialise the
            object
        :type kwargs: dict
        :return: user object
        :rtype: SCAutolib.models.user.User or SCAutolib.models.user.IPAUser
        """
        with json_file.open("r") as f:
            cnt = json.load(f)

        if cnt["user_type"] == UserType.local:
            user = User(username=cnt["username"],
                        password=cnt["password"])

        elif cnt["user_type"] == UserType.ipa:
            if "ipa_server" not in kwargs:
                raise SCAutolibException("IPA Server object was not provided. "
                                         "Can't load IPA user.")

            user = IPAUser(ipa_server=kwargs["ipa_server"],
                           username=cnt["username"],
                           password=cnt["password"])

        else:
            raise SCAutolibException(f"Unknown user type: {cnt['user_type']}")

        logger.debug(f"User {user.__class__} is loaded: {user.__dict__}")

        return user

    def add_user(self):
        """
        Add user to the local system with `useradd` bash command and set
        password for created user.
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
        Deletes the user
        """
        try:
            pwd.getpwnam(self.username)
            logger.info(f"Deleting the user {self.username}")
            run(['userdel', '-f', self.username], check=True)
        except KeyError:
            logger.info(f"User {self.username} is not present on the system")

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")


class IPAUser(User):
    """
    This class represents an IPA user.
    """
    default_password = "redhat"

    def __init__(self, ipa_server: IPAServerCA, *args, **kwargs):
        """
        Class for IPA user. IPA client should be configured first before
        creating an IPA user through this class.

        :param ipa_server: IPAServerCA object which provides the ipa hostname
        :type ipa_server: IPAServerCA
        :param username: Username for the system user
        :type username: str
        :param password: Password for the system user
        :type password: str
        :param key: Key to be associated with the user
        :type key: Path
        :param cert: Certificate to be associated with the user.
        :type cert: Path
        """

        super().__init__(*args, **kwargs)
        self.user_type = UserType.ipa
        self._meta_client = ipa_server.meta_client
        self._ipa_hostname = ipa_server.ipa_server_hostname

    def to_dict(self):
        d = super().to_dict()
        d.pop("_meta_client")
        d.pop("_ipa_hostname")
        return d

    def add_user(self):
        """
        Adds IPA user to IPA server.
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
        Deletes the user
        """
        try:
            r = self._meta_client.user_del(self.username)["result"]
            logger.info(f"User {self.username} is removed from the IPA server")
            logger.debug(r)
        except python_freeipa.exceptions.NotFound:
            pass
