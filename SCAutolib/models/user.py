"""
This module defines the User and IPAUser classes which can be used
to represent system and IPA users.

The classes contain the usual properties that defines a user, like username,
password, smart card pin, etc.

The classes implement add_user and delete_user methods which can be used to
create or remove a specified user in the system or in the specified IPA server.
"""
from shutil import rmtree

import json
import pwd
import python_freeipa
from pathlib import Path, PosixPath

from SCAutolib import run, logger, LIB_DUMP_USERS
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models import card as card_model
from SCAutolib.models.CA import IPAServerCA
from SCAutolib.models.file import OpensslCnf


class BaseUser:
    username: str = None
    password: str = None
    pin: str = None
    dump_file: Path = None
    _cnf: OpensslCnf = None
    _key: Path = None
    _cert: Path = None
    card_dir: Path = None
    _card: card_model.Card = None
    local: bool = None

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.dump_file = LIB_DUMP_USERS.joinpath(f"{self.username}.json")

    def to_dict(self):
        # Retype patlib.Path object to str
        d = {k: str(v) if type(v) in (PosixPath, Path) else v
             for k, v in self.__dict__.items()}

        if self._card and isinstance(self._card, card_model.VirtualCard):
            d.pop("_card")
            d["card"] = str(self._card.dump_file)

        return d

    @staticmethod
    def load(json_file, **kwargs):
        """
        Load values from user's JSON file to corresponding user object.

        :param json_file: path to JSON file to read from
        :type json_file: pathlib.Path
        :param kwargs: dictionary of additional values needed to initialise the
            object
        :return: object of local or IPA user
        :rtype: SCAutolib.models.user.User or SCAutolib.models.user.IPAUser
        """
        with json_file.open("r") as f:
            cnt = json.load(f)

        if "card_dir" not in cnt:
            user = BaseUser(username=cnt["username"], password=cnt["password"])
        elif cnt["local"]:
            user = User(local=cnt["local"],
                        username=cnt["username"],
                        card_dir=Path(cnt["card_dir"]),
                        password=cnt["password"],
                        pin=cnt["pin"],
                        key=cnt["_key"],
                        cert=cnt["_cert"])
        else:
            if "ipa_server" not in kwargs:
                raise SCAutolibException("IPA Server object does not provided. "
                                         "Can't load IPA user.")

            user = IPAUser(ipa_server=kwargs["ipa_server"],
                           local=cnt["local"],
                           username=cnt["username"],
                           card_dir=Path(cnt["card_dir"]),
                           password=cnt["password"],
                           pin=cnt["pin"],
                           key=cnt["_key"],
                           cert=cnt["_cert"])
        logger.debug(f"User {user.__class__} is loaded: {user.__dict__}")
        if "card" in cnt:
            return user, Path(cnt["card"])
        return user

    def add_user(self):
        """
        Add user to the local system with `useradd` bash command and set
        password for created user.
        :return:
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
            logger.info(f"User {self.username} is present on the system")


class User(BaseUser):
    """
    Generic class to represent system users.
    """

    def __init__(self, username: str, password: str, pin: str,
                 cnf: Path = None, key: Path = None, cert: Path = None,
                 card_dir: Path = None, local: bool = True):

        """
        :param username: Username for the system user
        :type username: str
        :param password: Password for the system user
        :type password: str
        :param pin: Smart card pin for the system user
        :type pin: str
        :param cnf: CNF file to be associated with the user
        :type cnf: Path
        :param key: Key to be associated with the user
        :type key: Path
        :param cert: Certificate to be associated with the user.
        :type cert: Path
        :param card_dir: Directory for the card. If None, standard
            home directory would be used (/home/<username>)
        :type card_dir: Path
        """

        self.username = username
        self.password = password
        self.pin = pin
        self.dump_file = LIB_DUMP_USERS.joinpath(f"{self.username}.json")
        self._cnf = cnf
        self.card_dir = card_dir if card_dir is not None \
            else Path("/home", self.username)
        self._key = key if key else self.card_dir.joinpath(f"key-{username}.pem")
        self._cert = cert \
            if cert else self.card_dir.joinpath(f"cert-{username}.pem")
        self.local = local

    @property
    def card(self):
        return self._card

    @card.setter
    def card(self, card: card_model.Card):
        if self._card:
            logger.error("Delete the existing card before adding a new one.")
            raise ValueError("A card is already assigned to this user")
        self._card = card

    @card.deleter
    def card(self):
        logger.info(f"Deleting the existing card from {self.username}")
        self._card = None

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: Path):
        logger.warning("Make sure to remove the existing key/cert "
                       "pairs before adding a new one.")
        self._key = key
        if self.card:
            self.card._private_key = key

    @key.deleter
    def key(self):
        logger.info("Deleting the current user key.")
        self._key = None

    @property
    def cert(self):
        return self._cert

    @cert.setter
    def cert(self, cert: Path):
        logger.warning("Make sure to remove the existing key/cert "
                       "pairs before adding a new one.")
        self._cert = cert
        if self.card:
            self.card._cert = cert

    @cert.deleter
    def cert(self):
        logger.info("Deleting the current user cert.")
        self._cert = None

    @property
    def cnf(self):
        return self._cnf

    @cnf.setter
    def cnf(self, cnf: Path):
        if self._cnf:
            logger.warning("Overriding current CNF file.")
        self._cnf = cnf

    @cnf.deleter
    def cnf(self):
        logger.info("Removing current CNF file.")
        self._cnf = None

    def delete_user(self):
        """
        Deletes the user and the content of user's card directory

        Note: card directory would be recursively deleted with a directory
        by itself.
        """
        try:
            pwd.getpwnam(self.username)
            logger.info(f"Deleting the user {self.username}")
            run(['userdel', '-f', self.username], check=True)
            if self.card_dir.exists():
                rmtree(self.card_dir)
                logger.debug("User's card directory "
                             f"{str(self.card_dir)} is removed")
        except KeyError:
            pass
        logger.info(f"User {self.username} is not present on the system")

    def gen_csr(self):
        """
        Method for generating local user specific CSR file that would be sent to
        the local CA for generating the certificate. CSR is generated using
        `openssl` command based on template CNF file.
        """
        csr_path = self.card_dir.joinpath(f"csr-{self.username}.csr")
        cmd = ["openssl", "req", "-new", "-nodes", "-key", self._key,
               "-reqexts", "req_exts", "-config", self._cnf, "-out", csr_path]
        run(cmd)
        return csr_path


class IPAUser(User):
    """
    This class is used to represent an IPA user.
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
        :param pin: Smart card pin for the system user
        :type pin: str
        :param cnf: CNF file to be associated with the user
        :type cnf: Path
        :param key: Key to be associated with the user
        :type key: Path
        :param cert: Certificate to be associated with the user.
        :type cert: Path
        """

        super().__init__(*args, **kwargs)
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
        Deletes the user and user's card directory.

        Note: card directory would be recursively deleted with a directory
        by itself.
        """
        try:
            r = self._meta_client.user_del(self.username)["result"]
            logger.info(f"User {self.username} is removed from the IPA server")
            logger.debug(r)
        except python_freeipa.exceptions.NotFound:
            pass
        if self.card_dir.exists():
            rmtree(self.card_dir)
            logger.info(f"User  {self.username} directory is removed.")

    def gen_csr(self):
        """
        Method for generating IPA user specific CSR file that would be sent to
        the IPA server for generating the certificate. CSR is generated using
        `openssl` command.
        """
        if not self._key:
            raise SCAutolibException("Can't generate CSR because private key "
                                     "is not set")
        csr_path = self.card_dir.joinpath(f"csr-{self.username}.csr")
        cmd = ["openssl", "req", "-new", "-days", "365",
               "-nodes", "-key", self._key, "-out",
               str(csr_path), "-subj", f"/CN={self.username}"]
        run(cmd)
        return csr_path
