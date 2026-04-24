"""
Manage different types of smart cards within the SCAutolib library.

This module implements the ``Card`` interface and specialized subclasses
for ``VirtualCard`` (software-emulated) and ``PhysicalCard`` (real
hardware). It provides common methods for insertion, removal, enrollment,
and system configuration.
"""


import json
import re
import time
import shutil
from typing import Any
from pathlib import Path
from traceback import format_exc

from SCAutolib import run, logger, TEMPLATES_DIR, LIB_DUMP_CARDS
from SCAutolib.exceptions import SCAutolibException, SCAutolibUnknownType, \
    SCAutolibIPAException, SCAutolibFileNotExists, SCAutolibCommandFailed
from SCAutolib.enums import CardType, UserType

from SCAutolib.models.file import SSSDConf
from SCAutolib.models.CA import BaseCA


class Card:
    """
    Provide an interface for different types of smart cards.

    Defines common attributes and abstract methods for subclasses. Includes
    shared logic for URI/label detection and SSSD integration.
    """

    _prepared: bool = False
    _inserted: bool = False
    _pattern: str = None

    name: str = None
    pin: str = None
    label: str = None
    cardholder: str = None
    CN: str = None
    UID: str = None
    expires: str = None
    card_type: str = None
    ca_name: str = None
    slot: str = None
    uri: str = None
    card_dir: Path = None
    uri: str = None

    dump_file: Path = None

    user = None
    ca = None

    def _set_uri(self):
        """
        Set the card URI by matching the output of p11tool.

        Uses the regular expression in ``self._pattern`` to find the token
        URL.

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

    def _set_label(self):
        """
        Set the card label by matching the output of pkcs11-tool.

        Searches for the token label using a regular expression.

        :return: None
        :rtype: None
        :raises SCAutolibException: If a matching label is not found or if
                                    multiple matching labels are detected.
        """
        if self.label:
            return

        cmd = ["pkcs11-tool", "-L"]
        out = run(cmd).stdout
        labels = re.findall(r"token label.*: (.*)", out)
        if len(labels) == 1:
            self.label = labels[0]
            logger.info(f"Card label is set to '{self.label}'")
        elif len(labels) == 0:
            logger.warning("Card label not set")
            raise SCAutolibException("Card label not found.")
        else:
            logger.warning("Multiple matching labels found. Label not set")
            logger.warning("Add a label field in the config.")
            raise SCAutolibException(
                "Multiple labels match expected pattern."
                "Possibly multiple slots available. Pass label in config.")

    def insert(self, update_sssd: bool):
        """
        Insert the smart card.

        This is an abstract method that concrete subclasses must implement.

        :param update_sssd: If ``True``, it setup the card CA and SSSD config.
        :type update_sssd: bool
        :return: None
        :rtype: None
        """
        ...

    def remove(self):
        """
        Remove the smart card.

        This is an abstract method that concrete subclasses must implement.

        :return: None
        :rtype: None
        """
        ...

    def enroll(self):
        """
        Enroll the card with certificates and keys.

        This is an abstract method that concrete subclasses must implement.

        :return: None
        :rtype: None
        """
        ...

    def setup_card_ca(self):
        """
        Configure the CA and SSSD for the smart card.

        Installs the CA certificate to the system and updates SSSD to
        link the user with the card.

        :return: None
        :rtype: None
        """
        if not self.ca_name or self._prepared:
            return

        logger.debug(f"Setup CA for card '{self.name}'")

        if not self.ca:
            self.ca = BaseCA.load(ca_name=self.ca_name)

        self.ca.update_ca_db(restart_sssd=True)

        sssd_conf = SSSDConf()
        if not sssd_conf.exists():
            sssd_conf.create()
        sssd_conf.update_matchrule(self.cardholder, self.CN)

        self._prepared = True

    def restore_card_ca(self, restore_conf: bool = False):
        """
        Remove the card CA and restore SSSD configuration.

        :param restore_conf: If ``True``, restores the ``sssd.conf`` file to
                             its original version.
        :type restore_conf: bool
        :return: None
        :rtype: None
        """
        if not self.ca_name or not self._prepared:
            return

        if not self.ca:
            self.ca = BaseCA.load(ca_name=self.ca_name)

        self.ca.restore_ca_db(restart_sssd=True)

        if restore_conf:
            sssd_conf = SSSDConf()
            sssd_conf.restore()

        self._prepared = False

    @staticmethod
    def load(
        card_file: Path = None, card_name: str = None,
        update_sssd: bool = False
    ):
        """
        Load a Card object from a JSON dump file.

        Determines the card type and instantiates the correct subclass.

        :param card_file: The ``pathlib.Path`` object pointing to the JSON file
                          containing the serialized card data.
        :type card_file: pathlib.Path
        :param card_name: The name of the card object to load.
        :type card_name: str, optional
        :param update_sssd: If ``True``, the SSSD configuration file will be
                            updated with a ``shadowutils`` rule for the user of
                            the loaded card.
        :type update_sssd: bool
        :return: An instance of the specific card class loaded with data from
                 the JSON file.
        :rtype: SCAutolib.models.card.Card
        :raises SCAutolibUnknownType: If an unknown card type is encountered in
                                     the JSON data.
        :raises FileExistsError: If the card file is not found.
        """
        if card_name and not card_file:
            card_file = LIB_DUMP_CARDS.joinpath(f"{card_name}.json")
            logger.debug(f"Loading card {card_name} from {card_file}")

        if not card_file.exists():
            raise FileExistsError(f"{card_file} does not exist")

        with card_file.open("r") as f:
            cnt = json.load(f)

        card = None
        if cnt["card_type"] == CardType.virtual:
            card = VirtualCard(cnt, softhsm2_conf=Path(cnt["softhsm"]))
        elif cnt["card_type"] == CardType.physical:
            card = PhysicalCard(cnt)
        else:
            raise SCAutolibUnknownType(
                f"Unknown card type: {cnt['card_type']}")

        if update_sssd:
            sssd_conf = SSSDConf()
            sssd_conf.update_matchrule(card.cardholder, card.CN)

        return card


class VirtualCard(Card):
    """
    Represent a virtual smart card managed as a systemd service.

    Provides methods for lifecycle management including creation,
    insertion, and enrollment using SoftHSM2. Supports context management.
    """

    _service_name: str = None
    _service_location: Path = None
    _softhsm2_conf: Path = None
    _nssdb: Path = None
    _template: Path = Path(TEMPLATES_DIR, "virt_cacard.service")
    _pattern = r"(pkcs11:model=PKCS%2315%20emulated;" \
               r"manufacturer=Common%20Access%20Card;serial=.*)"

    cnf = None

    def __init__(
        self, card_data, softhsm2_conf: Path = None, card_dir: Path = None,
        key: Path = None, cert: Path = None
    ):
        """
        Initialize a VirtualCard object and setup file paths.

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
        :raises SCAutolibFileNotExists: If the specified ``card_dir`` does not
                                        exist upon initialization.
        """
        self.uri = card_data.get("uri", None)

        self.name = card_data["name"]
        self.pin = card_data["pin"]
        self.label = card_data.get("label", None)
        self.cardholder = card_data["cardholder"]
        self.card_type = card_data["card_type"]
        self.CN = card_data["CN"]
        self.ca_name = card_data["ca_name"]
        self.slot = card_data["slot"] if card_data.get("slot", None) else "0"
        self.card_dir = card_dir if card_dir is not None \
            else Path(card_data["card_dir"])
        self._prepared = card_data.get("_prepared", False)
        self._inserted = card_data.get("_inserted", False)
        if not self.card_dir.exists():
            raise SCAutolibFileNotExists("Card root directory doesn't exists")
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

    def __call__(self, insert: bool = False) -> VirtualCard:
        """
        Enable the object to be used within a context manager.

        :param insert: If ``True``, the card's service will be
                       started (card inserted) upon calling the object.
        :type insert: bool
        :return: The ``VirtualCard`` instance itself, allowing context manager
                 entry.
        :rtype: SCAutolib.models.card.VirtualCard
        """
        if insert:
            self.setup_card_ca()
            self.insert()
        return self

    def __enter__(self) -> VirtualCard:
        """
        Enter the context manager and verify the service exists.

        :return: The ``VirtualCard`` instance.
        :rtype: SCAutolib.models.card.VirtualCard
        :raises SCAutolibFileNotExists: If the systemd service file for the
                                        virtual card does not exist.
        """
        self.setup_card_ca()
        if not self._service_location.exists():
            raise SCAutolibFileNotExists(
                "Service for virtual sc doesn't exists.")
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        """
        Exit the context manager and ensure the card is removed.

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

    def to_dict(self) -> dict[str, Any]:
        """
        Convert VirtualCard attributes into a dictionary for JSON storage.

        :return: A dictionary representation of the virtual card object's
                 attributes.
        :rtype: dict
        """
        return {
            "name": self.name,
            "pin": self.pin,
            "label": self.label,
            "cardholder": self.cardholder,
            "card_type": self.card_type,
            "CN": self.CN,
            "card_dir": str(self.card_dir),
            "key": str(self.key),
            "cert": str(self.cert),
            "uri": self.uri,
            "softhsm": str(self._softhsm2_conf),
            "ca_name": self.ca_name,
            "slot": self.slot,
            "_prepare": self._prepared,
            "_inserted": self._inserted,
        }

    @property
    def softhsm2_conf(self) -> Path:
        """
        Return the path to the SoftHSM2 configuration file.

        :return: A ``pathlib.Path`` object to the SoftHSM2 configuration file.
        :rtype: pathlib.Path
        """
        return self._softhsm2_conf

    @softhsm2_conf.setter
    def softhsm2_conf(self, conf: Path):
        """
        Set the SoftHSM2 configuration file path.

        :param conf: The ``pathlib.Path`` object to the SoftHSM2 configuration
                     file.
        :type conf: pathlib.Path
        :return: None
        :rtype: None
        :raises SCAutolibFileNotExists: If the provided configuration file path
                                        does not exist.
        """
        if not conf.exists():
            raise SCAutolibFileNotExists(f"File {conf} doesn't exist")
        self._softhsm2_conf = conf

    @property
    def service_location(self) -> Path:
        """
        Return the systemd service file location.

        :return: The service file path.
        :rtype: pathlib.Path
        """
        return self._service_location

    def insert(self, update_sssd: bool = False):
        """
        Insert the virtual card by starting its systemd service.

        :param update_sssd: If ``True``, it setup the card CA and SSSD config.
        :type update_sssd: bool
        :return: None
        :rtype: None
        """
        if update_sssd:
            self.setup_card_ca()

        cmd = ["systemctl", "start", self._service_name]
        run(cmd, check=True)
        time.sleep(2)  # to prevent error with fast restarting of the service
        logger.info(f"Smart card {self._service_name} is inserted")
        self._inserted = True

    def remove(self):
        """
        Remove the virtual card by stopping its systemd service.

        :return: None
        :rtype: None
        """
        if self._prepared:
            self.restore_card_ca()

        cmd = ["systemctl", "stop", self._service_name]
        run(cmd, check=True)
        time.sleep(2)  # to prevent error with fast restarting of the service
        logger.info(f"Smart card {self._service_name} is removed")
        self._inserted = False

    def enroll(self):
        """
        Enroll the virtual card by uploading certificates and keys.

        :return: None
        :rtype: None
        """
        cmd = ["pkcs11-tool", "--module", "libsofthsm2.so", "--slot-index",
               self.slot, "-w", self.key, "-y", "privkey", "--label",
               "test_key", "-p", self.pin, "--set-id", "0",
               "-d", "0"]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf})
        logger.debug(
            f"User key {self.key} is added to virtual smart card")

        cmd = ['pkcs11-tool', '--module', 'libsofthsm2.so', '--slot-index',
               self.slot, '-w', self.cert, '-y', 'cert', '-p', self.pin,
               '--label', "test_cert", '--set-id', "0", '-d', "0"]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf})
        logger.debug(
            f"User certificate {self.cert} is added to virtual smart card")

        # To get URI of the card, the card has to be inserted
        # Virtual smart card can't be started without a cert and a key uploaded
        # to it, so URI can be set only after uploading the cert and a key
        self.insert()
        try:
            self._set_uri()
            self._set_label()
            self.remove()
        except Exception as e:
            self.remove()
            raise e

    def create(self) -> VirtualCard:
        """
        Create components for the virtual card.

        Initializes a SoftHSM2 token, an NSS database, and a systemd
        service file.

        :return: The ``VirtualCard`` instance.
        :rtype: SCAutolib.models.card.VirtualCard
        :raises SCAutolibFileNotExists: If the SoftHSM2 configuration file is
                                        not found.
        """
        if not self._softhsm2_conf.exists():
            raise SCAutolibFileNotExists(
                "Can't proceed, SoftHSM2 conf not found.")

        self.card_dir.joinpath("tokens").mkdir(exist_ok=True)

        p11lib = "/usr/lib64/pkcs11/libsofthsm2.so"
        # Initialize SoftHSM2 token. An error would be raised if token with same
        # label would be created.
        cmd = ["softhsm2-util", "--init-token", "--free", "--label",
               self.name, "--so-pin", "12345678",
               "--pin", self.pin]
        run(cmd, env={"SOFTHSM2_CONF": self._softhsm2_conf}, check=True)
        logger.debug(
            f"SoftHSM token is initialized with label '{self.name}'")

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
        Delete the virtual card directory and systemd service file.

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

    def gen_csr(self) -> Path:
        """
        Generate a user-specific CSR using OpenSSL.

        :return: The ``pathlib.Path`` object to the generated CSR file.
        :rtype: pathlib.Path
        :raises SCAutolibIPAException: If the private key is not set when
                                       attempting to generate a CSR for an IPA
                                       user.
        """
        csr_path = self.card_dir.joinpath(f"csr-{self.name}.csr")
        if self.user.user_type == UserType.local:
            cmd = ["openssl", "req", "-new", "-nodes", "-key", self.key,
                   "-reqexts", "req_exts", "-config", self.cnf,
                   "-out", csr_path]
        else:
            if not self.key:
                raise SCAutolibIPAException(
                    "Can't generate CSR because private key is not set")
            cmd = ["openssl", "req", "-new", "-days", "365",
                   "-nodes", "-key", self.key, "-out",
                   csr_path, "-subj", f"/CN={self.CN}"]
        run(cmd)
        return csr_path


class PhysicalCard(Card):
    """
    Represent a physical smart card.

    Manipulates cards potentially connected via specialized hardware like
    Removinator.
    """

    reminator = None

    def __new__(class_, *args, **kwargs):
        """
        Create a new instance and initialize the Removinator singleton.
        """
        if not class_.reminator:
            from removinator.removinator import Removinator
            class_.reminator = Removinator()
        return object.__new__(class_)

    def __del__(self):
        """
        Ensure the card is removed from the hardware on object deletion.
        """
        if self.reminator.get_status()["current"] != 0:
            self.reminator.remove_card()

    def __init__(self, card_data: dict = None):
        """
        Initialize a PhysicalCard object and check hardware status.

        :param card_data: A dictionary containing details about the physical
                          card.
        :type card_data: dict, optional
        :return: None
        :rtype: None
        :raises SCAutolibException: If there is no card present in the
                                    specified slot.
        """
        if "slot" not in card_data:
            raise SCAutolibException("Physical cards need a slot field")

        self.uri = card_data.get("uri", None)

        self.card_data = card_data
        # Not sure we will need following, let's see later
        self.name = card_data["name"]
        self.pin = card_data["pin"]
        self.label = card_data.get("label", None)
        self.cardholder = card_data["cardholder"]
        self.CN = card_data["CN"]
        self.UID = card_data["UID"]
        self.expires = card_data["expires"]
        self.card_type = card_data["card_type"]
        self.ca_name = card_data["ca_name"]
        self.uri = card_data["uri"]
        self._prepared = card_data.get("_prepared", False)
        self._inserted = card_data.get("_inserted", False)

        self.slot = int(card_data["slot"])

        self.dump_file = LIB_DUMP_CARDS.joinpath(f"{self.name}.json")

        removinator_status = self.reminator.get_status()
        if self.slot not in removinator_status["present"]:
            raise SCAutolibException(f"The is no card in slot {self.slot}. "
                                     "Please connect a card to removinator.")
        if self.slot in removinator_status["locked"]:
            logger.warning(
                f"Card '{self.name}' is locked. "
                "Please check it unlock it manually.")
        if removinator_status["current"] != 0:
            self.reminator.remove_card()

        self.reminator.insert_card(self.slot)
        self._set_label()
        self.reminator.remove_card()

    def __call__(self, insert: bool = False) -> PhysicalCard:
        """
        Allow the card object to be called for context management.

        :param insert: If ``True``, the card will be inserted upon calling the
                       object.
        :type insert: bool
        :return: The ``PhysicalCard`` instance itself, allowing context manager
                 entry.
        :rtype: SCAutolib.models.card.PhysicalCard
        """
        if insert:
            self.insert()
        return self

    def __enter__(self) -> PhysicalCard:
        """
        Enter the context manager and login to the card.

        :return: The ``PhysicalCard`` instance.
        :rtype: SCAutolib.models.card.PhysicalCard
        """
        self.login_to_card()
        self.setup_card_ca()

        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        """
        Exit the context manager and ensure card restoration.

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

        if self._prepared:
            self.restore_card_ca()

        self.login_to_card(remove_after=True)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert PhysicalCard attributes into a dictionary.

        :return: A dictionary representation of the physical card object's
                 attributes.
        :rtype: dict
        """
        return {
            **self.card_data,
            "label": self.label,
            "_inserted": self._inserted,
            "_prepared": self._prepared
        }

    def insert(self, update_sssd: bool = True):
        """
        Insert the physical card via hardware interaction.

        :param update_sssd: If ``True``, it setup the card CA and SSSD config.
        :type update_sssd: bool
        :return: None
        :rtype: None
        """
        status = self.reminator.get_status()
        if self.slot in status["locked"]:
            raise SCAutolibException(
                f"Card '{self.name}' is locked and cannot be inserted. "
                "Please check and unlock the card manually.")

        if update_sssd:
            self.setup_card_ca()

        self.reminator.insert_card(self.slot)
        logger.debug(f"Inserted slot {self.slot} removinator card.")
        logger.debug(f"Removinator status: {self.reminator.get_status()}")

        self._inserted = True

    def remove(self):
        """
        Remove the physical card via hardware interaction.

        :return: None
        :rtype: None
        """
        if self._prepared:
            self.restore_card_ca()

        self.reminator.remove_card()
        logger.debug(f"Removed slot {self.slot} removinator card.")
        logger.debug(f"Removinator status: {self.reminator.get_status()}")

        self._inserted = False

    def delete(self):
        """
        Delete the physical card dump file.

        :return: None
        :rtype: None
        """
        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

    def login_to_card(self, remove_after: bool = None):
        """
        Login to the physical card using the pin.

        :param remove_after: If ``True``, removes the card after the login.
        :type remove_after: bool
        :return: None
        :rtype: None
        :raises SCAutolibCommandFailed: If login to card failed.
        """
        if not self.pin:
            return

        if not remove_after:
            remove_after = not self._inserted

        if not self._inserted:
            self.insert(update_sssd=False)

        try:
            logger.debug(f"Login to card '{self.name}'.")
            run(["pkcs11-tool", "-L", "--login", "--pin", self.pin],
                check=True)
            logger.debug("Login successful")
        except SCAutolibCommandFailed as e:
            logger.error("Failed to login to physical card.")
            self.remove()
            logger.error(
                f"Locking card in slot {self.slot}. Please investigate.")
            self.reminator.lock_card(self.slot)
            raise e

        if remove_after:
            self.remove()
