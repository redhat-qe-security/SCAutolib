"""
This module implements classes for communication with different types of cards
that we are using in the library. Those types are: virtual smart card, real
(physical) smart card in standard reader, cards in the removinator.
"""
import json
import re
import time
from pathlib import Path
from traceback import format_exc

from SCAutolib import run, logger, TEMPLATES_DIR, LIB_DUMP_CARDS
from SCAutolib.exceptions import SCAutolibException


class Card:
    """
    Interface for child classes. All child classes will rewrite common methods
    based on the type of the card.
    """
    uri: str = None
    dump_file: Path = None
    type: str = None
    _user = None
    _pattern: str = None

    def _set_uri(self):
        """
        Sets URI for given smart card. Uri is matched from ``p11tool`` command
        with regular expression. If URI is not matched, assertion exception
        would be raised

        :raise: AssertionError
        """
        cmd = ["p11tool", "--list-token-urls"]
        out = run(cmd).stdout
        urls = re.findall(self._pattern, out)
        assert len(urls) == 1, f"Card URI is not matched. Matched URIs: {urls}"
        self.uri = urls[0]

    def insert(self):
        """
        Insert the card.
        """
        ...

    def remove(self):
        """
        Remove the card.
        """
        ...

    def enroll(self):
        """
        Enroll the card (upload a certificate and a key on it)
        """
        ...

    @staticmethod
    def load(json_file, **kwars):
        with json_file.open("r") as f:
            cnt = json.load(f)

        card = None
        if cnt["type"] == "virtual":
            assert "user" in kwars.keys(), \
                "No user is provided to load the card."
            card = VirtualCard(user=kwars["user"],
                               softhsm2_conf=Path(cnt["softhsm"]))
            card.uri = cnt["uri"]
        else:
            raise SCAutolibException(
                f"Unknown card type: {cnt['type']}")
        return card


class VirtualCard(Card):
    """
    This class provides method for manipulating with virtual smart card. Virtual
    smart card by itself is represented by the systemd service in the system.
    The card relates to some user, so providing the user is essential for
    correct functioning of methods for the virtual smart card.

    Card root directory has to be created before calling any method
    """

    _service_name: str = None
    _service_location: Path = None
    _softhsm2_conf: Path = None
    _nssdb: Path = None
    _template: Path = Path(TEMPLATES_DIR, "virt_cacard.service")
    _pattern = r"(pkcs11:model=PKCS%2315%20emulated;" \
               r"manufacturer=Common%20Access%20Card;serial=.*)"
    _inserted: bool = False
    type = "virtual"

    def __init__(self, user, softhsm2_conf: Path = None):
        """
        Initialise virtual smart card. Constructor of the base class is also
        used.

        :param user: User of this card
        :type user: SCAutolib.models.user.User
        :param softhsm2_conf: path to SoftHSM2 configuration file
        :type softhsm2_conf: pathlib.Path
        """

        self.user = user
        assert self.user.card_dir.exists(), "Card root directory doesn't exists"

        self.dump_file = LIB_DUMP_CARDS.joinpath(f"card-{user.username}.json")

        self._private_key = self.user.key
        self._cert = self.user.cert

        self._service_name = f"virt-sc-{self.user.username}"
        self._service_location = Path(
            f"/etc/systemd/system/{self._service_name}.service")
        self.dump_file = LIB_DUMP_CARDS.joinpath(
            f"card-{self._user.username}.json")
        self._softhsm2_conf = softhsm2_conf if softhsm2_conf \
            else Path("/home", self.user.username, "softhsm2.conf")

    def __call__(self, insert: bool):
        """
        Call method for virtual smart card. It would be used in the context
        manager.

        :param insert: True if the card should be inserted, False otherwise
        :type insert: bool
        """
        if insert:
            self.insert()
        return self.__enter__()

    def __enter__(self):
        """
        Start of context manager for virtual smart card. The card would be
        inserted if ``insert`` parameter in constructor is specified.

        :return: self
        """
        assert self._service_location.exists(), \
            "Service for virtual sc doesn't exists."
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        """
        End of context manager for virtual smart card. If any exception was
        raised in the current context, it would be logged as an error.

        :param exp_type: Type of the exception
        :param exp_value: Value for the exception
        :param exp_traceback: Traceback of the exception
        """
        if exp_type is not None:
            logger.error("Exception in virtual smart card context")
            logger.error(format_exc())
        if self._inserted:
            self.remove()

    def to_dict(self):
        return {
            "softhsm": str(self._softhsm2_conf),
            "type": "virtual",
            "uri": self.uri,
            "username": self.user.username
        }

    @property
    def softhsm2_conf(self):
        return self._softhsm2_conf

    @softhsm2_conf.setter
    def softhsm2_conf(self, conf: Path):
        assert conf.exists(), "File doesn't exist"
        self._softhsm2_conf = conf

    @property
    def user(self):
        return self._user

    @user.setter
    def user(self, system_user):
        self._user = system_user
        self._nssdb = self.user.card_dir.joinpath("db")

    @property
    def service_location(self):
        return self._service_location

    def insert(self):
        """
        Insert virtual smart card by starting the corresponding service.
        """
        cmd = ["systemctl", "start", self._service_name]
        out = run(cmd, check=True)
        time.sleep(2)  # to prevent error with fast restarting of the service
        logger.info(f"Smart card {self._service_name} is inserted")
        self._inserted = True
        return out

    def remove(self):
        """
        Remove the virtual card by stopping the service
        """
        cmd = ["systemctl", "stop", self._service_name]
        out = run(cmd, check=True)
        time.sleep(2)  # to prevent error with fast restarting of the service
        logger.info(f"Smart card {self._service_name} is removed")
        self._inserted = False
        return out

    def enroll(self):
        """
        Upload certificate and private key to the virtual smart card (upload to
        NSS database) with pkcs11-tool.
        """
        cmd = ["pkcs11-tool", "--module", "libsofthsm2.so", "--slot-index",
               '0', "-w", self._user.key, "-y", "privkey", "--label",
               f"'{self._user.username}'", "-p", self._user.pin, "--set-id", "0",
               "-d", "0"]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf})
        logger.debug(
            f"User key {self._user.key} is added to virtual smart card")

        cmd = ['pkcs11-tool', '--module', 'libsofthsm2.so', '--slot-index', "0",
               '-w', self._user.cert, '-y', 'cert', '-p', self._user.pin,
               '--label', f"'{self._user.username}'", '--set-id', "0", '-d', "0"]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf})
        logger.debug(
            f"User certificate {self._user.cert} is added to virtual smart card")

        # To get URI of the card, the card has to be inserted
        # Virtual smart card can't be started without a cert and a key uploaded
        # to it, so URI can be set only after uploading the cert and a key
        with self:
            self.insert()
            self._set_uri()

    def create(self):
        """
        Creates SoftHSM2 token and systemd service for virtual smart card.
        Directory for NSS database is created in this method as separate DB is
        required for each virtual card.
        """

        assert self._softhsm2_conf.exists(), \
            "Can't proceed, SoftHSM2 conf doesn't exist"

        self.user.card_dir.joinpath("tokens").mkdir(exist_ok=True)

        p11lib = "/usr/lib64/pkcs11/libsofthsm2.so"
        # Initialize SoftHSM2 token. An error would be raised if token with same
        # label would be created.
        cmd = ["softhsm2-util", "--init-token", "--free", "--label",
               self.user.username, "--so-pin", "12345678",
               "--pin", self.user.pin]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf}, check=True)
        logger.debug(
            f"SoftHSM token is initialized with label '{self.user.username}'")

        # Initialize NSS db
        self._nssdb = self.user.card_dir.joinpath("db")
        self._nssdb.mkdir(exist_ok=True)
        run(f"modutil -create -dbdir sql:{self._nssdb} -force", check=True)
        logger.debug(f"NSS database is initialized in {self._nssdb}")

        out = run(f"modutil -list -dbdir sql:{self._nssdb}")
        if "library name: p11-kit-proxy.so" not in out.stdout:
            run(["modutil", "-force", "-add", 'SoftHSM PKCS#11', "-dbdir",
                 f"sql:{self._nssdb}", "-libfile", p11lib])
            logger.debug("SoftHSM support is added to NSS database")

        # Create systemd service
        with self._template.open() as tmp:
            with self._service_location.open("w") as f:
                f.write(tmp.read().format(username=self.user.username,
                                          softhsm2_conf=self._softhsm2_conf,
                                          card_dir=self.user.card_dir))

        logger.debug(f"Service is created in {self._service_location}")
        run("systemctl daemon-reload")

        return self
