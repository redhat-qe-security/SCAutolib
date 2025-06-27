"""
This module implements classes for interacting with different types of smart
cards used within the SCAutolib library. These include
``VirtualCard`` (software-emulated smart cards), ``PhysicalCard`` (real
smart cards in standard readers), and potentially cards connected via
specialized hardware like Removinator. The module provides a
common ``Card`` interface and specialized methods for operations like
inserting/removing cards, and enrolling (uploading keys and certificates).
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
    An interface class for different types of smart cards.
    It defines common attributes and abstract methods that child classes
    are expected to implement based on the
    specific card type. It also includes a static method
    for loading card objects from JSON dump files.
    """
    uri: str = None
    dump_file: Path = None
    type: str = None
    _pattern: str = None

    def _set_uri(self):
        """
        Sets the URI for the given smart card by matching it from the output
        of the ``p11tool --list-token-urls`` command using a regular expression
        (``self._pattern``). An exception is raised if
        no URI is matched, or if multiple URIs are found.

        :return: None
        :rtype: None
        :raises SCAutolibException: If a matching URI is not found or if
                                    multiple matching URIs are detected.
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
        Inserts the smart card.
        This is an abstract method that must be implemented by concrete card
        type subclasses.

        :return: None
        :rtype: None
        """

        ...

    def remove(self):
        """
        Removes the smart card.
        This is an abstract method that must be implemented by concrete card
        type subclasses.

        :return: None
        :rtype: None
        """

        ...

    def enroll(self):
        """
        Enrolls the card, typically by uploading a certificate and a key onto
        it.
        This is an abstract method that must be implemented by concrete card
        type subclasses.

        :return: None
        :rtype: None
        """

        ...

    @staticmethod
    def load(json_file):
        """
        Loads a ``Card`` object from a specified JSON dump file.
        It reads the JSON content, determines the card type, and then
        instantiates the appropriate card subclass with the loaded data.

        :param json_file: The ``pathlib.Path`` object pointing to the JSON file
                          containing the serialized card data.
        :type json_file: pathlib.Path
        :return: An instance of the specific card class loaded with data from
                 the JSON file.
        :rtype: SCAutolib.models.card.Card
        :raises SCAutolibException: If an unknown card type is encountered in
                                    the JSON data.
        """

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
    Represents a virtual smart card, which is implemented as a systemd service
    on the system. This class provides methods
    for managing the lifecycle of a virtual smart card, including its creation,
    insertion (starting the service), removal (stopping the service), and
    enrollment (uploading keys and certificates to its NSS database via
    SoftHSM2). It is designed to be used as a context manager.
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
        Initializes a ``VirtualCard`` object. It sets up
        card-specific attributes and paths for its files, service, and NSS
        database. The card's root directory must
        exist prior to calling any methods that interact with it.

        :param card_data: A dictionary containing details about the card,
                          such as ``pin``, ``cardholder``, ``name``, etc.
        :type card_data: dict
        :param softhsm2_conf: The ``pathlib.Path`` object to the SoftHSM2
                              configuration file used by this virtual card.
        :type softhsm2_conf: pathlib.Path, optional
        :param card_dir: The ``pathlib.Path`` object to the card's root
                         directory where its files will be saved.
        :type card_dir: pathlib.Path, optional
        :param key: The ``pathlib.Path`` object to the private key file. If
                    it exists, it will be used with the card.
        :type key: pathlib.Path, optional
        :param cert: The ``pathlib.Path`` object to the certificate file. If
                     it exists, it will be used with the card.
        :type cert: pathlib.Path, optional
        :return: None
        :rtype: None
        :raises FileNotFoundError: If the specified ``card_dir`` does not exist
                                   upon initialization.
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
        Allows the ``VirtualCard`` object to be called directly, enabling its
        use as part of a context manager.

        :param insert: If ``True``, the card's service will be
                       started (card inserted) upon calling the object.
        :type insert: bool
        :return: The ``VirtualCard`` instance itself, allowing context manager
                 entry.
        :rtype: SCAutolib.models.card.VirtualCard
        """

        if insert:
            self.insert()
        return self.__enter__()

    def __enter__(self):
        """
        Enters the context manager for the virtual smart card.
        It verifies that the virtual card's systemd service file exists
        before proceeding.

        :return: The ``VirtualCard`` instance.
        :rtype: SCAutolib.models.card.VirtualCard
        :raises FileNotFoundError: If the systemd service file for the virtual
                                   card does not exist.
        """

        if not self._service_location.exists():
            raise FileNotFoundError("Service for virtual sc doesn't exists.")
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        """
        Exits the context manager for the virtual smart card.
        If the card was inserted (its service started) upon entering the
        context, this method ensures it is removed (service stopped).
        Any exceptions raised within the context are logged.

        :param exp_type: The type of the exception that caused the context to
                         be exited, or ``None`` if no exception occurred.
        :param exp_value: The exception instance that caused the context to be
                          exited, or ``None``.
        :param exp_traceback: The traceback object associated with the
                              exception, or ``None``.
        :return: None
        :rtype: None
        """

        if exp_type is not None:
            logger.error("Exception in virtual smart card context")
            logger.error(format_exc())
        if self._inserted:
            self.remove()

    def to_dict(self):
        """
        Converts the ``VirtualCard`` object's attributes into a dictionary
        suitable for JSON serialization. It converts
        ``pathlib.Path`` objects to string representations for compatibility.

        :return: A dictionary representation of the virtual card object's
                 attributes.
        :rtype: dict
        """

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
        """
        Returns the path to the SoftHSM2 configuration file used by this
        virtual card.

        :return: A ``pathlib.Path`` object to the SoftHSM2 configuration file.
        :rtype: pathlib.Path
        """

        return self._softhsm2_conf

    @softhsm2_conf.setter
    def softhsm2_conf(self, conf: Path):
        """
        Sets the path to the SoftHSM2 configuration file for this virtual card.

        :param conf: The ``pathlib.Path`` object to the SoftHSM2 configuration
                     file.
        :type conf: pathlib.Path
        :return: None
        :rtype: None
        :raises FileNotFoundError: If the provided configuration file path does
                                   not exist.
        """

        if not conf.exists():
            raise FileNotFoundError(f"File {conf} doesn't exist")
        self._softhsm2_conf = conf

    @property
    def service_location(self):
        """
        Returns the ``pathlib.Path`` object to the systemd service file
        location for this virtual smart card.

        :return: The service file path.
        :rtype: pathlib.Path
        """

        return self._service_location

    def insert(self):
        """
        Inserts the virtual smart card by starting its corresponding systemd
        service. A short delay is included to prevent
        errors with fast service restarts.

        :return: The ``subprocess.CompletedProcess`` object from the systemctl
                 command.
        :rtype: subprocess.CompletedProcess
        """

        cmd = ["systemctl", "start", self._service_name]
        out = run(cmd, check=True)
        time.sleep(2)  # to prevent error with fast restarting of the service
        logger.info(f"Smart card {self._service_name} is inserted")
        self._inserted = True
        return out

    def remove(self):
        """
        Removes the virtual smart card by stopping its systemd service.
        A short delay is included to prevent errors with fast service restarts.

        :return: The ``subprocess.CompletedProcess`` object from the systemctl
                 command.
        :rtype: subprocess.CompletedProcess
        """

        cmd = ["systemctl", "stop", self._service_name]
        out = run(cmd, check=True)
        time.sleep(2)  # to prevent error with fast restarting of the service
        logger.info(f"Smart card {self._service_name} is removed")
        self._inserted = False
        return out

    def enroll(self):
        """
        Uploads a certificate and private key to the virtual smart card's
        internal NSS database via ``pkcs11-tool`` and SoftHSM2.
        After enrollment, the card is temporarily inserted to set its URI.

        :return: None
        :rtype: None
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
        Creates the necessary components for a virtual smart card, including
        initializing a SoftHSM2 token, setting up its NSS database, and
        creating the corresponding systemd service file.

        :return: The ``VirtualCard`` instance.
        :rtype: SCAutolib.models.card.VirtualCard
        :raises FileNotFoundError: If the SoftHSM2 configuration file is not
                                   found.
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
        Deletes the virtual card, including its dedicated directory (which
        contains certificates, SoftHSM2 token data, and NSS database), and
        removes its systemd service file.

        :return: None
        :rtype: None
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
        Generates a user-specific CSR (Certificate Signing Request) file using
        OpenSSL, based on a template CNF file and the user's private key.
        This CSR is then sent to a CA for certificate generation.

        :return: The ``pathlib.Path`` object to the generated CSR file.
        :rtype: pathlib.Path
        :raises SCAutolibException: If the private key is not set when
                                    attempting to generate a CSR for an IPA
                                    user.
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
    Represents a physical smart card.
    This class is intended to provide methods for manipulating physical cards,
    potentially connected via specialized hardware like a Removinator.

    Note: As of the provided code, this class is noted as 'Work In Progress'
    and not yet fully tested. Needs to be implemented with removinator.
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
        Initializes a ``PhysicalCard`` object.
        It sets up card attributes based on provided data and verifies the
        card's root directory exists.

        :param card_data: A dictionary containing details about the physical
                          card.
        :type card_data: dict, optional
        :param card_dir: The ``pathlib.Path`` object to the card's root
                         directory.
        :type card_dir: pathlib.Path, optional
        :return: None
        :rtype: None
        :raises FileNotFoundError: If the specified ``card_dir`` does not exist
                                   upon initialization.
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
        Allows the ``PhysicalCard`` object to be called directly, enabling its
        use as part of a context manager.

        :param insert: If ``True``, the card will be inserted upon calling the
                       object.
        :type insert: bool
        :return: The ``PhysicalCard`` instance itself, allowing context manager
                 entry.
        :rtype: SCAutolib.models.card.PhysicalCard
        """

        if insert:
            self.insert()
        return self.__enter__()

    def __enter__(self):
        """
        Enters the context manager for the physical smart card.

        :return: The ``PhysicalCard`` instance.
        :rtype: SCAutolib.models.card.PhysicalCard
        """

        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        """
        Exits the context manager for the physical smart card.
        If the card was marked as inserted, this method ensures it is removed
        upon exiting the context. Any exceptions raised
        within the context are logged.

        :param exp_type: The type of the exception that caused the context to
                         be exited, or ``None`` if no exception occurred.
        :param exp_value: The exception instance that caused the context to be
                          exited, or ``None``.
        :param exp_traceback: The traceback object associated with the
                              exception, or ``None``.
        :return: None
        :rtype: None
        """

        if exp_type is not None:
            logger.error("Exception in physical smart card context")
            logger.error(format_exc())
        if self._inserted:
            self.remove()

    def to_dict(self):
        """
        Converts the ``PhysicalCard`` object's attributes into a dictionary
        suitable for JSON serialization.

        :return: A dictionary representation of the physical card object's
                 attributes.
        :rtype: dict
        """

        return self.card_data

    @property
    def user(self):
        """
        Returns the cardholder's username associated with this physical card.

        :return: The cardholder's username.
        :rtype: str
        """

        return self.cardholder

    def insert(self):
        """
        Inserts the physical card.
        Note: This method is a placeholder and needs to be implemented
        to interact with Removinator.

        :return: None
        :rtype: None
        """

        ...

    def remove(self):
        """
        Removes the physical card.
        Note: This method is a placeholder and needs to be implemented
        to interact with Removinator.

        :return: None
        :rtype: None
        """

        ...
