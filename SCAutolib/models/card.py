"""
This module implements classes for communication with different types of cards
that we are using in the library. Those types are: virtual smart card, real
(physical) smart card in standard reader, cards in the removinator.
"""
import json
import re
import time
import shutil
from pathlib import Path
from traceback import format_exc

from SCAutolib import run, logger, TEMPLATES_DIR, LIB_DUMP_CARDS
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.enums import CardType, UserType


class Card:
    """
    Interface for child classes. All child classes will rewrite common methods
    based on the type of the card.
    """
    uri: str = None
    dump_file: Path = None
    type: str = None
    _pattern: str = None

    def _set_uri(self):
        """
        Sets URI for given smart card. Uri is matched from ``p11tool`` command
        with regular expression. If URI is not matched, exception is raised.

        :raise: SCAutolibException
        """
        cmd = ["p11tool", "--list-token-urls"]
        out = run(cmd).stdout
        urls = re.findall(self._pattern, out)
        if len(urls) == 1:
            self.uri = urls[0]
            logger.info(f"Card URI is set to {self.uri}")
        elif len(urls) == 0:
            logger.warning("URI not set")
            raise SCAutolibException("URI matching expected pattern not found.")
        else:
            logger.warning("Multiple matching URIs found. URI not set")
            raise SCAutolibException("Multiple URIs match expected pattern.")

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
    def load(json_file):
        with json_file.open("r") as f:
            cnt = json.load(f)

        card = None
        if cnt["card_type"] == CardType.virtual:
            card = VirtualCard(cnt, softhsm2_conf=Path(cnt["softhsm"]))
#            card.uri = cnt["uri"]
        elif cnt["card_type"] == CardType.physical:
            card = PhysicalCard(cnt)
        else:
            raise SCAutolibException(
                f"Unknown card type: {cnt['card_type']}")
        return card


class VirtualCard(Card):
    """
    This class provides methods for operations on virtual smart card. Virtual
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

    name: str = None
    pin: str = None
    cardholder: str = None
    CN: str = None
    UID: str = None
    key: Path = None
    cert: Path = None
    card_dir: Path = None
    card_type: str = None
    ca_name: str = None
    slot: str = None
    user = None
    cnf = None

    def __init__(self, card_data, softhsm2_conf: Path = None,
                 card_dir: Path = None, key: Path = None, cert: Path = None):
        """
        Initialise virtual smart card. Constructor of the base class is also
        used.

        :param card_data: dict containing card details as pin, cardholder etc.
        :type card_data: dict
        :param softhsm2_conf: path to SoftHSM2 configuration file
        :type softhsm2_conf: pathlib.Path
        :param card_dir: path to card directory where card files will be saved
        :type card_dir: pathlib.Path
        :param key: path to key - if the key exist it will be used with the card
        :type key: pathlib.Path
        :param cert: path to certificate. If file exist it will be used with the
            card
        :type cert: pathlib.Path
        """
        self.name = card_data["name"]
        self.pin = card_data["pin"]
        self.cardholder = card_data["cardholder"]
        self.card_type = card_data["card_type"]
        self.CN = card_data["CN"]
        self.ca_name = card_data["ca_name"]
        self.card_dir = card_dir if card_dir is not None \
            else Path(card_data["card_dir"])
        if not self.card_dir.exists():
            raise FileNotFoundError("Card root directory doesn't exists")
        self.dump_file = LIB_DUMP_CARDS.joinpath(f"{self.name}.json")
        self.key = key \
            if key else self.card_dir.joinpath(f"key-{self.name}.pem")
        self.cert = cert \
            if cert else self.card_dir.joinpath(f"cert-{self.name}.pem")
        self._service_name = self.name
        self._service_location = Path(
            f"/etc/systemd/system/{self._service_name}.service")
        self._nssdb = self.card_dir.joinpath("db")
        self._softhsm2_conf = softhsm2_conf if softhsm2_conf \
            else Path(self.card_dir, "softhsm2.conf")

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
        if not self._service_location.exists():
            raise FileNotFoundError("Service for virtual sc doesn't exists.")
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
            "name": self.name,
            "pin": self.pin,
            "cardholder": self.cardholder,
            "card_type": self.card_type,
            "CN": self.CN,
            "card_dir": str(self.card_dir),
            "key": str(self.key),
            "cert": str(self.cert),
            "uri": self.uri,
            "softhsm": str(self._softhsm2_conf),
            "ca_name": self.ca_name,
            "slot": self.slot
        }

    @property
    def softhsm2_conf(self):
        return self._softhsm2_conf

    @softhsm2_conf.setter
    def softhsm2_conf(self, conf: Path):
        if not conf.exists():
            raise FileNotFoundError(f"File {conf} doesn't exist")
        self._softhsm2_conf = conf

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
               '0', "-w", self.key, "-y", "privkey", "--label",
               "test_key", "-p", self.pin, "--set-id", "0",
               "-d", "0"]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf})
        logger.debug(
            f"User key {self.key} is added to virtual smart card")

        cmd = ['pkcs11-tool', '--module', 'libsofthsm2.so', '--slot-index', "0",
               '-w', self.cert, '-y', 'cert', '-p', self.pin,
               '--label', "test_cert", '--set-id', "0", '-d', "0"]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf})
        logger.debug(
            f"User certificate {self.cert} is added to virtual smart card")

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

        if not self._softhsm2_conf.exists():
            raise FileNotFoundError("Can't proceed, SoftHSM2 conf not found.")

        self.card_dir.joinpath("tokens").mkdir(exist_ok=True)

        p11lib = "/usr/lib64/pkcs11/libsofthsm2.so"
        # Initialize SoftHSM2 token. An error would be raised if token with same
        # label would be created.
        cmd = ["softhsm2-util", "--init-token", "--free", "--label",
               self.name, "--so-pin", "12345678",
               "--pin", self.pin]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf}, check=True)
        logger.debug(
            f"SoftHSM token is initialized with label '{self.cardholder}'")

        # Initialize NSS db
        self._nssdb = self.card_dir.joinpath("db")
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
                f.write(tmp.read().format(username=self.cardholder,
                                          softhsm2_conf=self._softhsm2_conf,
                                          card_dir=self.card_dir))

        logger.debug(f"Service is created in {self._service_location}")
        run("systemctl daemon-reload")

        return self

    def delete(self):
        """
        Deletes the virtual card directory which contains certs, SoftHSM2 token
        and NSS database. Also removes the systemd service for virtual smart
        card.
        """
        shutil.rmtree(self.card_dir)
        logger.info(f"Virtual card dir of {self.name} removed")

        self._service_location.unlink()
        run("systemctl daemon-reload", sleep=3)
        logger.debug(f"Service {self._service_name} was removed")

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

    def gen_csr(self):
        """
        Method for generating user specific CSR file that would be sent to the
        CA for generating the certificate. CSR is generated using 'openssl`
        command based on template CNF file.
        """
        csr_path = self.card_dir.joinpath(f"csr-{self.cardholder}.csr")
        if self.user.user_type == UserType.local:
            cmd = ["openssl", "req", "-new", "-nodes", "-key", self.key,
                   "-reqexts", "req_exts", "-config", self.cnf,
                   "-out", csr_path]
        else:
            if not self.key:
                raise SCAutolibException("Can't generate CSR because private "
                                         "key is not set")
            cmd = ["openssl", "req", "-new", "-days", "365",
                   "-nodes", "-key", self.key, "-out",
                   csr_path, "-subj", f"/CN={self.cardholder}"]
        run(cmd)
        return csr_path


class PhysicalCard(Card):
    """
    :TODO PhysicalCard is not yet tested, it's Work In Progress
        This class provides methods allowing to manipulate physical cards
        connected via removinator.
    """
    _inserted: bool = False

    name: str = None
    pin: str = None
    cardholder: str = None
    CN: str = None
    UID: str = None
    expires: str = None
    card_type: str = None
    ca_name: str = None
    slot: str = None
    uri: str = None
    card_dir: Path = None

    def __init__(self, card_data: dict = None, card_dir: Path = None):
        """
        TODO this is not yet tested, insert and remove methods need to be
            implemented with removinator
        Initialise object for physical smart card. Constructor of the base class
        is also used.
        """
        self.card_data = card_data
        # Not sure we will need following, let's see later
        self.name = card_data["name"]
        self.pin = card_data["pin"]
        self.cardholder = card_data["cardholder"]
        self.CN = card_data["CN"]
        self.UID = card_data["UID"]
#        self.expires = card_data["expires"]
#        self.card_type = card_data["card_type"]
#        self.ca_name = card_data["ca_name"]
        self.slot = card_data["slot"]
        self.uri = card_data["uri"]
        self.card_dir = card_dir
        if not self.card_dir.exists():
            raise FileNotFoundError("Card root directory doesn't exists")

        self.dump_file = LIB_DUMP_CARDS.joinpath(f"{self.name}.json")

    def __call__(self, insert: bool):
        """
        Call method for physical smart card. It would be used in the context
        manager.

        :param insert: True if the card should be inserted, False otherwise
        :type insert: bool
        """
        if insert:
            self.insert()
        return self.__enter__()

    def __enter__(self):
        """
        Start of context manager for physical smart card. The card would be
        inserted if ``insert`` parameter in constructor is specified.

        :return: self
        """
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        """
        End of context manager for physical smart card. If any exception was
        raised in the current context, it would be logged as an error.

        :param exp_type: Type of the exception
        :param exp_value: Value for the exception
        :param exp_traceback: Traceback of the exception
        """
        if exp_type is not None:
            logger.error("Exception in physical smart card context")
            logger.error(format_exc())
        if self._inserted:
            self.remove()

    def to_dict(self):
        """
        Customising default property for better serialisation for storing to
        JSON format.

        :return: dictionary with all values. Path objects are typed to string.
        :rtype: dict
        """
        return self.card_data

    @property
    def user(self):
        return self.cardholder

    def insert(self):
        """
        Insert physical card using removinator
        """
        ...

    def remove(self):
        """
        Remove physical card using removinator
        """
        ...
