"""
This module defines the User and IPAUser classes which can be used
to represent system and IPA users.

The classes contain the usual properties that defines a user, like username,
password, smart card pin, etc.

The classes implement add_user and delete_user methods which can be used to
create or remove a specified user in the system or in the specified IPA server.
"""
from pathlib import Path

from SCAutolib.models.CA import IPAServerCA
from SCAutolib import run, logger


class User:
    """
    Generic class to represent system users.
    """

    def __init__(self, username: str, password: str, pin: str, card=None,
                 cnf: Path = None, key: Path = None, cert: Path = None):

        """
        :param username: Username for the system user
        :type: str
        :param password: Password for the system user
        :type str
        :param pin: Smart card pin for the system user
        :type str
        :param card: Card to be associated with the user
        :type Card
        :param cnf: CNF file to be associated with the user
        :type Path
        :param key: Key to be associated with the user
        :type Path
        :param cert: Certificate to be associated with the user.
        :type Path
        """

        self.username = username
        self.password = password
        self.pin = pin
        self._card = card
        self._cnf = cnf
        self._key = key
        self._cert = cert
        self.card_dir = None

    @property
    def card(self):
        return self._card

    @card.setter
    def card(self, card: Path):
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

    def delete_user(self):
        logger.info(f"Deleting the user {self.username}")
        run(['userdel', '-f', self.username], check=True)

    def add_user(self):
        run(['useradd', '-m', '-p', self.password, self.username], check=True)
        self.card_dir = f"/home/{self.username}"
        logger.info(f"Creating new user {self.username}")


class IPAUser(User):
    """
    This class is used to represent an IPA user.
    """

    def __init__(self, ipa_server: IPAServerCA, username: str, password: str,
                 pin: str, card=None, cnf: Path = None, key: Path = None,
                 cert: Path = None):

        """
        :param ipa_server: IPAServerCA object which provides the ipa hostname
        :type IPAServerCA
        :param username: Username for the system user
        :type: str
        :param password: Password for the system user
        :type str
        :param pin: Smart card pin for the system user
        :type str
        :param card: Card to be associated with the user
        :type Card
        :param cnf: CNF file to be associated with the user
        :type Path
        :param key: Key to be associated with the user
        :type Path
        :param cert: Certificate to be associated with the user.
        :type Path
        """

        super().__init__(username, password, pin, card, cnf, key, cert)
        self._meta_client = ipa_server.meta_client

        self._meta_client.login("admin", ipa_server._ipa_server_admin_passwd)

    def add_user(self):
        r = self._meta_client.user_add(self.username, self.username,
                                       self.username, self.username,
                                       o_userpassword=self.password,
                                       o_homedirectory=f"/home/{self.username}")
        self.card_dir = f"/home/{self.username}"
        logger.debug(r)
        logger.info(f"User {self.username} is added to the IPA server")

    def delete_user(self):
        r = self._meta_client.user_del(self.username)["result"]
        logger.info(f"User {self.username} is removed from the IPA server")
        run(['rm', '-r', '-f', f"/home/{self.username}"], check=True)
        logger.info(f"User {self.username} directory is removed.")
        logger.debug(r)
