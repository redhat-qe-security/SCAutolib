"""
This module defines the User and IPAUser classes which can be used
to represent system and IPA users.

The classes contain the usual properties that defines a user, like username,
password, smart card pin, etc.

The classes implement add_user and delete_user methods which can be used to
create or remove a specified user in the system or in the specified IPA server.
"""
import json
import pwd
import python_freeipa
from pathlib import Path, PosixPath

from SCAutolib import run, logger, LIB_DUMP_USERS, LIB_DUMP_CARD
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models import card as card_model
from SCAutolib.models.CA import IPAServerCA


class BaseUser:
    username = None
    password = None
    pin = None
    dump_file = None
    _cnf = None
    _key = None
    _cert = None
    card_dir = None


class User(BaseUser):
    """
    Generic class to represent system users.
    """
    _card = None
    dump_file: Path = None

    def __init__(self, username: str, password: str, pin: str,
                 cnf: Path = None, key: Path = None, cert: Path = None,
                 card_dir: Path = None):

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
        self._key = key
        self._cert = cert
        self.card_dir = card_dir if card_dir is not None \
            else Path("/home", self.username)

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
        logger.info("Deleting the existing card from {self.username}")
        self._card = None

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: Path):
        logger.warning("Make sure to remove the existing key/cert "
                       "pairs before adding a new one.")
        self._key = key

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

    @property
    def __dict__(self):
        """
        Customising default property for better serialisation for storing to
        JSON format.

        :return: dictionary with all values. Path objects are typed to string.
        :rtype: dict
        """
        dict_ = super().__dict__.copy()
        for k, v in dict_.items():
            if type(v) in (PosixPath, Path):
                dict_[k] = str(v)

        if self._card:
            dict_["_card"] = str(
                LIB_DUMP_CARD.joinpath(f"card-{self.username}.json"))
        return dict_

    def delete_user(self):
        try:
            pwd.getpwnam(self.username)
            logger.info(f"Deleting the user {self.username}")
            run(['userdel', '-f', self.username], check=True)
        except KeyError:
            pass
        logger.info(f"User {self.username} is not present on the system")

    def add_user(self, force=False):
        try:
            pwd.getpwnam(self.username)
            msg = f"User {self.username} already exists on this " \
                  f"machine. Username should be unique to avoid " \
                  f"future problems with collisions"
            logger.critical(msg)
            # raise SCAutolibException(msg)
        except KeyError:
            logger.debug(f"Creating new user {self.username}")
            cmd = ['useradd', '-m', self.username]
            run(cmd, check=True)
            cmd = ["passwd", self.username, "--stdin"]
            run(cmd, input=self.password)
            logger.info(f"User {self.username} is present ons the system")

    def gen_csr(self):
        csr_path = self.card_dir.joinpath(f"csr-{self.username}.csr")
        cmd = ["openssl", "req", "-new", "-nodes", "-key", self._key,
               "-reqexts", "req_exts", "-config", self._cnf, "-out", csr_path]
        run(cmd)
        return csr_path

    def load(self):
        with self.dump_file.open("r") as f:
            cnt = json.load(f)
        cnt["card_dir"] = Path(cnt["card_dir"])

        for k, v in cnt.__dict__.items():
            setattr(self, k, v)
        return self


class IPAUser(User):
    """
    This class is used to represent an IPA user.
    """

    def __init__(self, ipa_server: IPAServerCA, username: str, password: str,
                 pin: str, cnf: Path = None, key: Path = None,
                 cert: Path = None, card_dir: Path = None):
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

        super().__init__(username, password, pin, cnf, key, cert, card_dir)
        self._meta_client = ipa_server.meta_client

    @property
    def __dict__(self):
        """
        Customising default property for better serialisation for storing to
        JSON format.

        :return: dictionary with all values. Path objects are typed to string.
        :rtype: dict
        """
        dict_ = super().__dict__
        dict_.pop("_meta_client")
        return dict_

    def add_user(self):
        try:
            r = self._meta_client.user_add(self.username, self.username,
                                           self.username, self.username,
                                           o_userpassword=self.password,
                                           o_homedirectory=str(self.card_dir))
            logger.debug(r)
            logger.info(f"User {self.username} is added to the IPA server")
        except python_freeipa.exceptions.DuplicateEntry:
            msg = f"User {self.username} already exists on the " \
                  f"IPA server. Username should be unique to avoid " \
                  f"future problems with collisions"
            logger.critical(msg)
            # raise SCAutolibException(msg)

    def delete_user(self):
        r = self._meta_client.user_del(self.username)["result"]
        logger.info(f"User {self.username} is removed from the IPA server")
        run(['rm', '-r', '-f', f"/home/{self.username}"], check=True)
        logger.info(f"User {self.username} directory is removed.")
        logger.debug(r)

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

    def load(self, ipa_server: IPAServerCA):
        super(IPAUser, self).load()
        self._meta_client = ipa_server.meta_client
        return self
