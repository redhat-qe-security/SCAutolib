from .card import Card
from enum import Enum, auto


class UserType(Enum):
    """
    Type of users used in the library
    """
    LOCAL_USER = auto()
    IPA_USER = auto()


class User:
    username: str = None
    password: str = None
    card: Card = None
    user_type: UserType = None

    def __init__(self, username: str, password: str):
        """
        Constructor for the user.

        :param username: username for the user
        :type: str
        :param password: password to for the user
        :type: str
        """

    def add_user(self):
        ...

    def del_user(self):
        ...

    def add_card(self, card: Card):
        """
        Add card to the user

        :param card: object of Card class
        :type: Card
        :return:
        """
        self.card = card

    def create_csr(self):
        """Create a CSR for the user with specified parameters"""

    def add_cert(self):
        """Add certificate to the user"""


class IPAUser(User):
    """
    Model for IPA user
    """
    def add_user(self):
        """Add user to the IPA server"""
        # Logic for adding user to IPA


class LocalUser(User):
    """
    Model for local user
    """
    def add_user(self):
        """"""
        # Logic for adding local user
