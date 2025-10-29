"""
This module implements classes that represent Certificate Authorities (CA)
within the SCAutolib framework.
It provides a foundational ``BaseCA`` class and specialized subclasses
for ``LocalCA`` (local OpenSSL-based CAs), ``CustomCA`` (for physical cards),
and ``IPAServerCA`` (for FreeIPA integrated CAs).
These classes encapsulate CA-specific attributes and methods for
operations such as certificate requests, signing, revocation, and managing
the system's CA trust store (``sssd_auth_ca_db.pem``).
"""


import os
import re
import json
import python_freeipa
from typing import Union
from cryptography import x509
from hashlib import sha256
from pathlib import Path, PosixPath
from python_freeipa import exceptions
from python_freeipa.client_meta import ClientMeta
from shutil import rmtree, copy2
from socket import gethostname

from SCAutolib import TEMPLATES_DIR, logger, run, LIB_DIR, LIB_DUMP_CAS, \
    LIB_BACKUP
from SCAutolib.exceptions import SCAutolibException, SCAutolibUnknownType, \
    SCAutolibIPAException, SCAutolibFileNotExists
from SCAutolib.models.file import OpensslCnf
from SCAutolib.enums import CAType


class BaseCA:
    """
    A foundational class serving as an interface and base implementation for
    different types of Certificate Authorities (CAs) within SCAutolib. It
    defines common properties like certificate and key paths, and provides
    shared methods for CA-related operations, especially managing the file used
    by the System Security Services Daemon (SSSD) to store a list of
    Certificate Authority (CA) certificates (``sssd_auth_ca_db.pem``).
    """
    dump_file: Path = None
    ca_type: str = None
    _ca_cert: Path = None
    _ca_key: Path = None
    _ca_pki_db: Path = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")
    _ca_original_path: Path = LIB_BACKUP.joinpath("ca-db-original.backup")

    @property
    def cert(self):
        """
        Returns the path to the CA's certificate file.

        :return: A ``pathlib.Path`` object pointing to the CA certificate.
        :rtype: pathlib.Path
        """

        return self._ca_cert

    def request_cert(self, csr: Union[str, Path], username: str, cert_out: Path):
        """
        Requests a certificate from the CA for a given username using a
        CSR (Certificate Signing Request). The signed certificate is then
        duplicated to the specified output path.
        This method is a placeholder in ``BaseCA`` and its implementation
        varies depending on the specific CA type (e.g., local, IPA).

        :param csr: The path to the CSR file.
        :type csr: str
        :param username: The subject name for the certificate.
        :type username: str
        :param cert_out: The path where the signed certificate should be stored.
        :type cert_out: pathlib.Path
        :return: The path where the certificate is stored.
        :rtype: pathlib.Path
        """

        ...

    def setup(self):
        """
        Configures the Certificate Authority.
        This method is a placeholder in ``BaseCA`` and its implementation
        varies depending on the specific CA type (e.g., local, IPA).

        :return: None
        :rtype: None
        """

        ...

    def update_ca_db(self, restart_sssd: bool = False):
        """
        Updates the system's ``sssd_auth_ca_db.pem`` file with the CA's
        certificate defined in this CA object.
        It backs up the original ``sssd_auth_ca_db.pem`` if it exists and
        ensures the CA certificate is added if not already present.
        SELinux context is restored on the database file after modification.

        :param restart_sssd: If ``True``, SSSD service will be restarted.
        :type restart_sssd: bool
        :return: None
        :rtype: None
        """

        with self._ca_cert.open("r") as f_cert:
            root_cert = f_cert.read()

        if self._ca_pki_db.exists():
            with self._ca_pki_db.open() as f:
                with self._ca_original_path.open('w') as backup:
                    backup.write(f.read())
            # Check if current CA cert is already present in the sssd auth db
            with self._ca_pki_db.open("a+") as f:
                f.seek(0)
                data = f.read()
                if root_cert not in data:
                    f.write(root_cert)
        else:
            # Create /etc/sssd/pki directory if it doesn't exist
            self._ca_pki_db.parents[0].mkdir(exist_ok=True)
            with self._ca_pki_db.open("w") as f:
                f.write(root_cert)
        logger.debug(
            f"CA certificate {self._ca_cert} is copied to {self._ca_pki_db}")
        # Restoring SELinux context on the sssd auth db
        run(f"restorecon -v {self._ca_pki_db}")
        logger.info("Local CA is updated")

        if restart_sssd:
            run(["systemctl", "restart", "sssd"], sleep=5)

    def restore_ca_db(self, restart_sssd: bool = False):
        """
        Restores the ``sssd_auth_ca_db.pem`` file to its state before it was
        modified by this CA object. It uses the backed-up
        original file for restoration. If no backup exists, it will simply
        remove the current ``sssd_auth_ca_db.pem`` if it's present.

        :param restart_sssd: If ``True``, SSSD service will be restarted.
        :type restart_sssd: bool
        :return: None
        :rtype: None
        """

        if self._ca_original_path.exists():
            logger.debug("Found original version of sssd_auth_ca_db.pem")
            with self._ca_original_path.open() as backup, \
                    self._ca_pki_db.open("w") as f:
                f.write(backup.read())
            self._ca_original_path.unlink()
        else:
            logger.debug("Original version of sssd_auth_ca_db.pem not found")
            if self._ca_pki_db.exists():
                self._ca_pki_db.unlink()
        logger.info(f"Restored {self._ca_pki_db} to original version")

        if restart_sssd:
            run(["systemctl", "restart", "sssd"], sleep=5)

    def sign_cert(self):
        """
        Signs a certificate.
        This method is a placeholder in ``BaseCA`` and its implementation
        varies depending on the specific CA type (e.g., local, IPA).

        :return: None
        :rtype: None
        """

        ...

    def revoke_cert(self, cert: Path):
        """
        Revokes a given certificate.
        This method is a placeholder in ``BaseCA`` and its implementation
        varies depending on the specific CA type (e.g., local, IPA).

        :param cert: The ``pathlib.Path`` object to the certificate to be
                     revoked.
        :type cert: pathlib.Path
        :return: None
        :rtype: None
        """

        ...

    @staticmethod
    def load(json_file: Union[str, Path] = None, ca_name: str = None):
        """
        Loads a CA object from a JSON file.
        It reads the JSON content, determines the CA type, and then
        instantiates the appropriate CA subclass with the loaded attributes.

        :param json_file: The ``pathlib.Path`` object pointing to the JSON file
                          containing the serialized CA data.
        :type json_file: pathlib.Path
        :return: An instance of the specific CA class loaded with data from the
                 JSON file.
        :rtype: SCAutolib.models.CA.BaseCA
        :raises SCAutolibUnknownType: If the CA object has an unknown type in the
                                     JSON file, or if the data is invalid for
                                     IPA CA initialization.
        """
        if ca_name and not json_file:
            json_file = LIB_DUMP_CAS.joinpath(f"{ca_name}.json")
            logger.debug(f"Loading CA {ca_name} from {json_file}")

        with json_file.open("r") as f:
            cnt = json.load(f)

        if cnt["ca_type"] == CAType.ipa:
            ca = IPAServerCA(ip_addr=cnt["_ipa_server_ip"],
                             server_hostname=cnt["_ipa_server_hostname"],
                             root_passwd=cnt["_ipa_server_root_passwd"],
                             admin_passwd=cnt["_ipa_server_admin_passwd"],
                             client_hostname=cnt["_ipa_client_hostname"],
                             domain=cnt["_ipa_server_domain"],
                             realm=cnt["_ipa_server_realm"])
        elif cnt["ca_type"] == CAType.custom:
            ca = CustomCA(name=cnt["name"], ca_cert=cnt["ca_cert"])
        elif cnt["ca_type"] == CAType.local:
            ca = LocalCA(root_dir=cnt["root_dir"])
        else:
            raise SCAutolibUnknownType("CA object has unknown type. Only ipa, "
                                       "custom and local types are supported. "
                                       "CA object not loaded")

        logger.debug(f"CA {cnt['name']} is loaded from file {json_file}")
        return ca

    @staticmethod
    def factory(path: Path = None, cnf: OpensslCnf = None,
                ca_cert: str = None, ca_name: str = None,
                create: bool = False):
        """
        A factory function to create or load Certificate Authority (CA) objects
        based on the provided parameters. It can initialize
        a new CA instance or load an existing one from a JSON dump file.

        :param path: The ``pathlib.Path`` object to the CA's root directory.
                     This is used when creating a new ``LocalCA`` instance.
        :type path: pathlib.Path, optional
        :param cnf: An ``OpensslCnf`` object representing the OpenSSL
                    configuration file for the CA. Used when creating a new
                    ``LocalCA``.
        :type cnf: SCAutolib.models.file.OpensslCnf, optional
        :param ca_cert: The CA cert to be added to the custom CA object. This
                        data is used when creating a new ``CustomCA`` for
                        physical cards.
        :type ca_cert: str, optional
        :param ca_name: The name of the CA to load. This parameter is used when
                        ``create`` is ``False`` to identify the specific CA
                        JSON dump file.
        :type ca_name: str, optional
        :param create: If ``True``, a new CA object will be created
                    (either ``LocalCA`` or ``CustomCA``). If ``False``,
                    an existing CA object will be loaded from a dump file.
        :type create: bool
        :return: An initialized CA object (either ``LocalCA``, ``CustomCA``, or
                ``IPAServerCA`` instance).
        :rtype: SCAutolib.models.CA.BaseCA
        """
        if not create:
            ca = BaseCA.load(LIB_DUMP_CAS.joinpath(f"{ca_name}.json"))
            return ca

        if ca_cert:  # create custom CA for physical card
            ca = CustomCA(name=ca_name, ca_cert=ca_cert)
            return ca
        elif path:  # create new CA object for virtual card
            ca = LocalCA(root_dir=path, cnf=cnf)
            return ca
        else:
            raise SCAutolibException(
                "To create a cert, either a path or ca_cert should be "
                "provided")


class LocalCA(BaseCA):
    """
    Represents a local Certificate Authority (CA) that is created and managed
    directly on the system, typically used as a CA for virtual smart cards.
    It extends ``BaseCA`` and provides specific
    implementations for setting up the CA's directory structure, generating
    self-signed certificates, and managing CRLs (Certificate Revocation Lists)
    using OpenSSL.
    """
    template = Path(TEMPLATES_DIR, "ca.cnf")
    ca_type = CAType.local
    ca_name = "local_ca"
    dump_file = LIB_DUMP_CAS.joinpath(f"{ca_name}.json")

    def __init__(self, root_dir: Path = None, cnf: OpensslCnf = None):
        """
        Initializes a ``LocalCA`` object.
        It sets up paths for the CA's root directory, configuration files,
        certificate, and key, but the actual file system setup is performed
        by the ``setup()`` method.

        :param root_dir: The ``pathlib.Path`` object to the root directory
                         where the CA files will be stored. Defaults to
                         ``/etc/SCAutolib/ca``.
        :type root_dir: pathlib.Path, optional
        :param cnf: An ``OpensslCnf`` object representing the OpenSSL CNF file
                    used for the CA.
        :type cnf: SCAutolib.models.file.OpensslCnf, optional
        :return: None
        :rtype: None
        :raises SCAutolibFileNotExists: If the specified ``root_dir`` does not
                                        exist upon initialization.
        """

        self.name = LocalCA.ca_name
        self.ca_type = LocalCA.ca_type
        self.root_dir: Path = Path("/etc/SCAutolib/ca") if root_dir is None \
            else Path(root_dir)
        if not self.root_dir.exists():
            raise SCAutolibFileNotExists(
                "Root directory of CA does not exist.")
        self._conf_dir: Path = self.root_dir.joinpath("conf")
        self._newcerts: Path = self.root_dir.joinpath("newcerts")
        self._certs: Path = self.root_dir.joinpath("certs")
        self._crl: Path = self.root_dir.joinpath("crl", "root.pem")
        self._ca_pki_db = BaseCA._ca_pki_db

        self._ca_cnf: OpensslCnf = cnf if cnf else OpensslCnf(
            conf_type="CA",
            filepath=self.root_dir.joinpath("ca.cnf"),
            replace=str(self.root_dir))
        self._ca_cert = self.root_dir.joinpath("rootCA.pem")
        self._ca_key = self.root_dir.joinpath("rootCA.key")

        self._serial: Path = self.root_dir.joinpath("serial")
        self._index: Path = self.root_dir.joinpath("index.txt")

    @property
    def cnf(self):
        """
        Returns the OpenSSL CNF object associated with this local CA.

        :return: An ``OpensslCnf`` object.
        :rtype: SCAutolib.models.file.OpensslCnf
        """

        return self._ca_cnf

    @cnf.setter
    def cnf(self, cnf: OpensslCnf):
        """
        Sets the OpenSSL CNF object for this local CA.

        :param cnf: The ``OpensslCnf`` object to set.
        :type cnf: SCAutolib.models.file.OpensslCnf
        :return: None
        :rtype: None
        :raises SCAutolibFileNotExists: If the provided CNF file does not exist.
        """

        if not cnf.path.exists():
            raise SCAutolibFileNotExists("CNF file does not exist")
        self._ca_cnf = cnf

    def to_dict(self):
        """
        Customizes the serialization of the ``LocalCA`` object to a dictionary
        format suitable for storing as JSON.
        It converts ``pathlib.Path`` objects to strings.

        :return: A dictionary containing all serializable attributes of the
                 ``LocalCA`` instance.
        :rtype: dict
        """

        dict_ = {k: str(v) if type(v) is PosixPath else v
                 for k, v in super().__dict__.items()}
        if self._ca_cnf:
            dict_["_ca_cnf"] = str(self._ca_cnf.path)
        return dict_

    @property
    def is_installed(self):
        """
        Checks if the local CA is fully installed on the system.
        This involves verifying the existence of the root directory, CA
        certificate, private key, CNF file, and other required files,
        as well as checking if the CA certificate is present in
        ``sssd_auth_ca_db.pem``.

        :return: ``True`` if the local CA is completely installed and configured;
                 ``False`` otherwise.
        :rtype: bool
        """

        try:
            result = all([self.root_dir.exists(),
                          self._ca_cert.exists(),
                          self._ca_key.exists(),
                          self._ca_cnf.path.exists(),
                          self._conf_dir.exists(),
                          self._newcerts.exists(),
                          self._certs.exists(),
                          self._crl.exists(),
                          self._serial.exists(),
                          self._index.exists()])
            if result and self._ca_pki_db.exists():
                with self._ca_pki_db.open("r") as f:
                    with self._ca_cert.open("r") as cert:
                        result &= cert.read() in f.read()
        except Exception as e:
            logger.error(e)
            return False
        return result

    def setup(self):
        """
        Configures the local CA by creating its required directory and file
        structure. It generates a self-signed root certificate
        and private key using OpenSSL, and initializes the CRL (Certificate
        Revocation List).

        :return: None
        :rtype: None
        :raises SCAutolibException: If the CA's CNF file is not set.
        :raises SCAutolibFileNotExists: If the CA's CNF file  does not exist.
        """
        if self._ca_cnf is None:
            raise SCAutolibException("CA CNF file is not set")
        elif not self._ca_cnf.path.exists():
            raise SCAutolibFileNotExists("CA CNF does not exist")

        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._newcerts.mkdir(exist_ok=True)
        self._certs.mkdir(exist_ok=True)
        self._crl.parent.mkdir(exist_ok=True)

        with self._serial.open("w") as f:
            f.write("01")

        self._index.touch()

        # Generate self-signed certificate
        cmd = ['openssl', 'req', '-batch', '-config', self._ca_cnf.path,
               '-x509', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout',
               self._ca_key, '-sha256', '-set_serial', '0',
               '-extensions', 'v3_ca', '-out', self._ca_cert]
        run(cmd, check=True)
        logger.info(f"CA private key is generated into {self._ca_key}")
        logger.info(
            f"CA self-signed certificate is generated into {self._ca_cert}")

        # Configuring CRL
        run(['openssl', 'ca', '-config', self._ca_cnf.path, '-gencrl',
             '-out', self._crl], check=True)

        logger.info("Local CA files are prepared")

    def request_cert(self, csr: Path, username: str,
                     cert_out: Path = None) -> Path:
        """
        Creates and signs a certificate from a given CSR (Certificate Signing
        Request) using the local CA's private key.
        The signed certificate is stored in a predefined location (e.g.,
        ``<root ca directory>/certs/<username>.pem``) or a specified output
        path.

        :param csr: The ``pathlib.Path`` object pointing to the CSR file.
        :type csr: pathlib.Path
        :param username: The subject name to be included in the certificate.
        :type username: str
        :param cert_out: An optional ``pathlib.Path`` object specifying where
                         the signed certificate should be copied. It can be
                         a directory or a file. If a file, ``.pem`` extension
                         is ensured. If ``None``, the certificate is created in
                         the default directory.
        :type cert_out: pathlib.Path, optional
        :return: The ``pathlib.Path`` object to the location of the signed
                 certificate.
        :rtype: pathlib.Path
        """

        if cert_out is not None:
            if cert_out.is_dir():
                cert_out = cert_out.joinpath(f"{username}.pem")
            elif cert_out.is_file() and cert_out.suffixes[-1] != ".pem":
                cert_out = cert_out.with_suffix(".pem")
        else:
            cert_out = self._certs.joinpath(f"{username}.pem")
        cmd = ["openssl", "ca", "-config", self._ca_cnf.path,
               "-batch", "-keyfile", str(self._ca_key), "-in", str(csr),
               "-notext", "-days", "365", "-extensions", "usr_cert",
               "-out", str(cert_out)]
        run(cmd, check=True)
        return cert_out

    def revoke_cert(self, cert: Path):
        """
        Revokes a given certificate using the local CA.
        It updates the CA's CRL (Certificate Revocation List) after revocation.

        :param cert: The ``pathlib.Path`` object to the certificate file to be
                     revoked.
        :type cert: pathlib.Path
        :return: None
        :rtype: None
        """

        cmd = ['openssl', 'ca', '-config', self._ca_cnf.path, '-revoke', cert]
        run(cmd, check=True)
        cmd = ['openssl', 'ca', '-config', self._ca_cnf.path, '-gencrl',
               '-out', self._crl]
        run(cmd, check=True)
        logger.info("Certificate is revoked")

    def cleanup(self):
        """
        Removes the entire root directory of the local CA, including all
        its generated files, certificates, and keys.
        It also deletes the associated JSON dump file.

        :return: None
        :rtype: None
        """

        logger.warning(f"Removing local CA {self.root_dir}")
        for file in self.root_dir.iterdir():
            if file.is_file():
                file.unlink()
            elif file.is_dir():
                rmtree(file)

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

        logger.info(f"Local CA from {self.root_dir} is removed")


class CustomCA(BaseCA):
    """
    Represents a custom Certificate Authority (CA), typically used for
    physical smart cards which might have pre-existing or read-only root CA
    certificates. This class provides methods
    for integrating such external CA certificates into the system.

    :TODO: As of the provided code, this class is noted as not yet fully
    tested or functional.
    """

    def __init__(self, name: str, ca_cert: str):
        """
        Initializes a ``CustomCA`` object from provided card data.
        It sets up the CA's name, certificate path, and dump file location
        based on the card's information.

        :param card_data: A dictionary containing details about the card,
                          including the CA's name and certificate data
                          (e.g., ``card["ca_name"]``, ``card["ca_cert"]``).
        :type card_data: dict
        :return: None
        :rtype: None
        """

        self.ca_type = CAType.custom
        self.name = name
        self.ca_cert = ca_cert
        self.dump_file = LIB_DUMP_CAS.joinpath(f"{self.name}.json")
        self.root_dir: Path = LIB_DIR.joinpath(self.name)
        self._ca_cert = self.root_dir.joinpath(f"{self.name}.pem")
        self._ca_pki_db: Path = BaseCA._ca_pki_db

    def setup(self):
        """
        Sets up the ``CustomCA`` by creating its root directory and copying
        the provided CA certificate content into a PEM file within that
        directory.

        :return: None
        :rtype: None
        :raises SCAutolibException: If the CA certificate content is not
                                    provided in ``self.ca_cert``.
        """

        self.root_dir.mkdir(parents=True, exist_ok=True)
        if self.ca_cert is None:
            raise SCAutolibException(
                f"CA cerf for {self.name} not found")
        with self._ca_cert.open('w') as newcert:
            newcert.write(self.ca_cert)
        logger.info("Local CA files are prepared")

    def cleanup(self):
        """
        Removes the entire root directory of the local CA, including all
        its generated files, certificates, and keys.
        It also deletes the associated JSON dump file.

        :return: None
        :rtype: None
        """

        logger.warning(f"Removing custom CA '{self.name}'")

        if self._ca_cert.exists():
            self._ca_cert.unlink()

        if self.root_dir.exists():
            rmtree(self.root_dir)

        if self.dump_file.exists():
            self.dump_file.unlink()
            logger.debug(f"Removed {self.dump_file} dump file")

        logger.info(f"Local CA from {self.root_dir} is removed")

    def to_dict(self):
        """
        Customizes the serialization of the ``CustomCA`` object to a dictionary
        format suitable for JSON storage.
        It converts ``pathlib.Path`` objects to their string representations.

        :return: A dictionary containing all serializable attributes of the
                 ``CustomCA`` instance.
        :rtype: dict
        """

        return {
            "ca_type": self.ca_type,
            "name": self.name,
            "ca_cert": self.ca_cert
        }


class IPAServerCA(BaseCA):
    """
    Represents an IPA (Identity Management for Linux) server with its integrated
    Certificate Authority. This class facilitates
    communication with the IPA server, primarily using
    ``python_freeipa.client_meta.ClientMeta``
    for administrative tasks. It handles IPA client setup
    on the current system for smart card authentication, including fetching
    and executing the necessary setup scripts from the IPA server.
    """
    ca_type = CAType.ipa
    ca_name = "IPA"
    _ca_cert: Path = Path("/etc/ipa/ca.crt")
    _ipa_server_ip: str = None
    _ipa_server_hostname: str = None
    _ipa_server_domain: str = None
    _ipa_server_admin_passwd: str = None
    _ipa_server_realm: str = None
    _ipa_client_hostname: str = None
    _ipa_server_root_passwd: str = None
    _ipa_client_script = Path(LIB_DIR, "ipa-client-sc.sh")
    meta_client: ClientMeta = None
    dump_file = LIB_DUMP_CAS.joinpath("ipa-server.json")

    def __init__(self, ip_addr: str, server_hostname: str, domain: str,
                 admin_passwd: str, root_passwd: str, client_hostname: str,
                 realm: str = None):
        """
        Initializes an ``IPAServerCA`` object, setting up attributes for the
        IPA server and client. It also performs
        initial network configurations (adding to ``/etc/hosts``) and
        establishes a logged-in ``ClientMeta`` instance for API interactions.

        :param ip_addr: The IP address of the IPA server.
        :type ip_addr: str
        :param server_hostname: The hostname of the IPA server.
        :type server_hostname: str
        :param domain: The domain name of the IPA server.
        :type domain: str
        :param admin_passwd: The password for the IPA ``admin`` user.
        :type admin_passwd: str
        :param root_passwd: The root user password on the IPA server (for SSH
                            access to fetch scripts).
        :type root_passwd: str
        :param client_hostname: The desired hostname for the client system that
                                will be joined to IPA.
        :type client_hostname: str
        :param realm: The Kerberos realm. If ``None``, the ``domain`` in
                      uppercase will be used as the realm.
        :type realm: str, optional
        :return: None
        :rtype: None
        """
        self.ca_type = IPAServerCA.ca_type
        self.name = IPAServerCA.ca_name
        self._ipa_server_ip = ip_addr
        self._ipa_server_hostname = server_hostname
        self._add_to_hosts()  # So we can log in to the IPA before setup

        self._ipa_server_domain = domain
        self._ipa_server_admin_passwd = admin_passwd
        self._ipa_server_realm = realm if realm is not None else domain.upper()
        self._ipa_client_hostname = client_hostname
        self._ipa_server_root_passwd = root_passwd

        self._meta_client_login()

    @property
    def is_installed(self):
        """
        Checks if the IPA client is installed on the current system.
        This is determined by the existence of the ``/etc/ipa`` directory and
        the ``ca.crt`` file within it, which is provided by the IPA server.

        :return: ``True`` if the IPA client is detected as installed; ``False``
                 otherwise.
        :rtype: bool
        """

        d = Path("/etc/ipa")
        result = d.exists()
        if result:
            result = d.joinpath("ca.crt")
        return result

    @property
    def domain(self):
        """
        Returns the domain name of the IPA server.

        :return: The IPA server's domain as a string.
        :rtype: str
        """

        return self._ipa_server_domain

    @property
    def ipa_server_hostname(self):
        """
        Returns the hostname of the IPA server this object is configured to
        interact with.

        :return: The IPA server's hostname as a string.
        :rtype: str
        """
        return self._ipa_server_hostname

    def to_dict(self):
        """
        Customizes the serialization of the ``IPAServerCA`` object to a
        dictionary format suitable for JSON storage.
        It excludes the ``meta_client`` attribute as it is not serializable.

        :return: A dictionary containing all serializable attributes of the
                 ``IPAServerCA`` instance.
        :rtype: dict
        """
        dict_: dict = super().__dict__.copy()
        dict_.pop("meta_client")
        return dict_

    def setup(self):
        """
        Configures the IPA client on the current host to join the IPA server.
        This involves setting up ``/etc/resolv.conf``,
        setting the hostname, installing the IPA client package, and running
        a specific script (fetched from the IPA server) to configure smart card
        login with IPA. It also adjusts the IPA's
        global password policy.

        :return: None
        :rtype: None
        :raises Exception: If the IPA client installation fails.
        """

        logger.info(f"Start setup of IPA client on the system for "
                    f"{self._ipa_server_hostname} IPA server.")

        self._add_to_resolv()
        self._set_hostname()

        logger.info("Installing IPA client")
        try:
            run(["ipa-client-install", "-p", "admin",
                 "--password", self._ipa_server_admin_passwd,
                 "--server", self._ipa_server_hostname,
                 "--domain", self._ipa_server_domain,
                 "--realm", self._ipa_server_realm,
                 "--hostname", self._ipa_client_hostname,
                 "--force", "--force-join", "--no-ntp",
                 "--no-dns-sshfp", "--mkhomedir", "--unattended"],
                input="yes")
        except:
            logger.critical("Installation of IPA client is failed")
            rmtree("/etc/ipa/*")
            logger.debug("Directory /etc/ipa is removed")
            raise SCAutolibIPAException("IPA client installation failed.")
        logger.debug("IPA client is installed")

        try:
            copy2("/tmp/cont-data/config-client-for-smart-card-auth.sh",
                  self._ipa_client_script)
            logger.info("Script for setting up IPA client for smart cards was "
                        f"found and copied to {self._ipa_client_script}")
        except FileNotFoundError:
            logger.info("Script for setting up IPA client for smart cards was "
                        "not found. It will be generated on IPA server and "
                        "fetched")
            self._get_sc_setup_script()
        run("kinit admin", input=self._ipa_server_admin_passwd)
        run(f'bash {self._ipa_client_script} /etc/ipa/ca.crt', check=True)
        logger.debug("Setup of IPA client for smart card is finished")

        self._meta_client_login()

        policy = self.meta_client.pwpolicy_show(a_cn="global_policy")["result"]
        if ["0"] != policy["krbminpwdlife"]:
            self.meta_client.pwpolicy_mod(a_cn="global_policy",
                                          o_krbminpwdlife=0)
            logger.debug("Minimal kerberos password lifetime is set to 0 days")
        if "365" not in policy["krbmaxpwdlife"]:
            self.meta_client.pwpolicy_mod(a_cn="global_policy",
                                          o_krbmaxpwdlife=365)
            logger.debug(
                "Maximum kerberos password lifetime is set to 365 days")

        # TODO: add to restore client host name
        logger.info("IPA client is configured on the system.")

    def _meta_client_login(self):
        """
        Establishes a connection and logs in to the IPA server as the ``admin``
        user using ``python_freeipa.client_meta.ClientMeta``.
        The connection does not use SSL verification.

        :return: None
        :rtype: None
        """
        try:
            self.meta_client: ClientMeta = ClientMeta(self._ipa_server_hostname,
                                                      verify_ssl=False)
            self.meta_client.login("admin", self._ipa_server_admin_passwd)
            logger.info("Connected to IPA via meta client")
        except python_freeipa.exceptions.BadRequest:
            logger.warning("Can't login to the IPA server. "
                           "Client might be not configured")

    def _set_hostname(self):
        """
        Sets the hostname of the current system to the specified IPA client
        hostname using ``hostnamectl``.

        :return: None
        :rtype: None
        """
        run(f"hostnamectl set-hostname {self._ipa_client_hostname} --static")
        logger.debug(f"Hostname is set to {self._ipa_client_hostname}")

    def _add_to_resolv(self):
        """
        Adds the IPA server's IP address as the primary nameserver in
        ``/etc/resolv.conf``. It checks if the nameserver is
        already present to avoid duplication.

        :return: None
        :rtype: None
        """
        nameserver = f"nameserver {self._ipa_server_ip}"
        pattern = rf"^nameserver\s+{self._ipa_server_ip}\s*"
        with open("/etc/resolv.conf", "r") as f:
            cnt = f.read()
        logger.debug(f"Original resolv.conf:\n{cnt}")
        if re.match(pattern, cnt) is None:
            logger.warning(f"Nameserver {self._ipa_server_ip} is not "
                           "present in /etc/resolv.conf. Adding...")
            cnt = (nameserver + "\n" + cnt)
            with open("/etc/resolv.conf", "w") as f:
                f.write(cnt)
            logger.info(
                "IPA server is added to /etc/resolv.conf as first nameserver")

        with open("/etc/resolv.conf", "r") as f:
            logger.debug(f"New resolv.conf\n{f.read()}")

    def _add_to_hosts(self):
        """
        Adds the IPA server's IP address and hostname to the ``/etc/hosts``
        file if the entry does not already exist.

        :return: None
        :rtype: None
        """
        entry = f"{self._ipa_server_ip} {self._ipa_server_hostname}"
        with open("/etc/hosts", "r+") as f:
            cnt = f.read()
            if entry not in cnt:
                f.write(f"\n{entry}\n")
                logger.warning(
                    f"New entry {entry} for IPA server is added to /etc/hosts")
            logger.info(
                f"Entry for IPA server {entry} presents in the /etc/hosts")

    def _get_sc_setup_script(self):
        """
        Fetches the smart card setup script for IPA client from the IPA server
        via SSH. This script is generated on the server-side
        and is then saved to a predefined local path for execution.
        It authenticates to the IPA server as ``admin`` and then as ``root``
        via SSH.

        :return: None
        :rtype: None
        :raises SCAutolibException: If the script is not correctly copied or
                                    if SSH connection/command execution fails.
        """
        import paramiko
        from invoke import Responder
        from fabric.connection import Connection

        kinitpass = Responder(
            pattern=f"Password for admin@{self._ipa_server_realm}: ",
            response=f"{self._ipa_server_admin_passwd}\n")
        logger.debug("Start receiving client script for setting up smart card "
                     "on IPA client")
        with Connection(self._ipa_server_ip, user="root",
                        connect_kwargs={
                            "password": self._ipa_server_root_passwd}) as c:
            # TODO Delete this block when PR in paramiko will be accepted
            # https://github.com/paramiko/paramiko/issues/396
            #### noqa:E266
            paramiko.PKey.get_fingerprint = \
                lambda x: sha256(x.asbytes()).digest()
            c.client = paramiko.SSHClient()
            c.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            #### noqa:E266
            c.open()
            # in_stream = False is required because while testing with pytest
            # it collision appears with capturing of the output.
            logger.debug("Running kinit on the IPA server")
            c.run("kinit admin", pty=True,
                  watchers=[kinitpass], in_stream=False)
            result = c.run("ipa-advise config-client-for-smart-card-auth",
                           hide=True, in_stream=False)
            logger.debug("Script is generated on server side")
            with open(self._ipa_client_script, "w") as f:
                f.write(result.stdout)

        if os.stat(self._ipa_client_script).st_size == 0:
            msg = "Script for IPA client smart card setup is not correctly " \
                  "copied to the host"
            logger.error(result.stdout)
            logger.error(result.stderr)
            raise SCAutolibException(msg)

        logger.debug("File for setting up IPA client for smart cards is "
                     f"copied to {self._ipa_client_script}")

    def request_cert(self, csr: Path, username: str, cert_out: Path):
        """
        Requests a certificate from the IPA CA for a given username using a CSR
        (Certificate Signing Request). This method wraps the
        ``python_freeipa.client_meta.ClientMeta.cert_request`` function,
        extracts the certificate from the response, and saves it in PEM format
        to the specified output path.

        :param csr: The ``pathlib.Path`` object to the CSR file.
        :type csr: pathlib.Path
        :param username: The principal (subject) name for the certificate.
        :type username: str
        :param cert_out: The ``pathlib.Path`` object where the certificate should
                         be stored. Can be a directory or a file. If it is
                         directory then the file will be saved there with name
                         ``<username>.pem``. If it's a file without a ``.pem``
                         extension, ``.pem`` will be appended.
        :type cert_out: pathlib.Path
        :return: A ``pathlib.Path`` object to the location of the PEM certificate
                 file.
        :rtype: pathlib.Path
        """

        with csr.open() as f:
            csr_content = f.read()
        r = self.meta_client.cert_request(a_csr=csr_content,
                                          o_principal=username)
        logger.debug(r)
        cert = r["result"]["certificate"]

        if cert_out.is_dir():
            cert_out = cert_out.joinpath(f"{username}.pem")
        else:
            cert_out = cert_out.with_suffix(".pem")

        with cert_out.open("w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n"
                    f"{cert}\n"
                    f"-----END CERTIFICATE-----")
        return cert_out

    def add_user(self, user: str):
        """
        Adds a given user to the IPA server. This method wraps the
        ``python_freeipa.client_meta.ClientMeta.user_add`` function, extracting
        necessary user fields for the IPA API call.
        For simplicity, ``givenname``, ``uid``, ``sn``, and ``cn`` are set to
        the username.

        :param user_obj: The user object to be added to the IPA server.
                         Expected to have ``username`` and ``password``
                         attributes.
        :type user_obj: SCAutolib.models.user.User
        :return: None
        :rtype: None
        """

        r = self.meta_client.user_add(user.username, user.username,
                                      user.username, user.username,
                                      o_userpassword=user.password)
        logger.debug(r)
        logger.info(f"User {user.username} is added to the IPA server")

    def del_user(self, user: str):
        """
        Removes a user from the IPA server.
        This method wraps the
        ``python_freeipa.client_meta.ClientMeta.user_del`` function.

        :param user_obj: The user object to be deleted from the IPA server.
                         Expected to have a ``username`` attribute.
        :type user_obj: SCAutolib.models.user.User
        :return: None
        :rtype: None
        """

        r = self.meta_client.user_del(user.username)["result"]
        logger.debug(r)
        logger.info(f"User {user.username} is removed from the IPA server")

    def revoke_cert(self, cert_path: Path):
        """
        Revokes a given certificate on the IPA server.
        This method wraps the
        ``python_freeipa.client_meta.ClientMeta.cert_revoke`` function and
        extracts the serial number of the certificate from the provided PEM
        file for revocation.

        :param cert_path: The ``pathlib.Path`` object to the certificate file in
                          PEM format to be revoked.
        :type cert_path: pathlib.Path
        :return: The serial number of the revoked certificate.
        :rtype: int
        """
        with cert_path.open("rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        r = self.meta_client.cert_revoke(cert.serial_number)
        logger.debug(r)
        logger.info(f"Certificate {cert.serial_number} is revoked")
        return cert.serial_number

    def cleanup(self):
        """
        Removes the IPA client from the system and also attempts to remove
        the corresponding host entry from the IPA server.
        It executes the ``ipa-client-install --uninstall`` command on the
        client.

        :return: None
        :rtype: None
        :raises SCAutolibCommandFailed: If ``ipa-client-install --uninstall``
                                        fails with an unexpected return code.
        """

        logger.warning("Removing IPA client from the host "
                       f"{gethostname()}")
        try:
            r = self.meta_client.host_del(
                a_fqdn=gethostname(), o_updatedns=True)["result"]
            logger.debug(r)
            assert r["failed"] == [], "Deleting of the host is failed"
        except exceptions.NotFound:
            logger.error(f"Current hostname ({gethostname()}) is not found "
                         f"on the IPA server")
        # Return code 2 means that the IPA client is not configured
        run(["ipa-client-install", "--uninstall", "-U"], return_code=[0, 2])
        logger.info("IPA client is removed.")

    @staticmethod
    def factory():
        """
        Creates and returns an ``IPAServerCA`` object. This function
        loads the IPA server CA configuration from its JSON dump file.
        It specifically asserts that the loaded CA is an instance of
        ``IPAServerCA``.

        .. note: Creating new IPA server with CA is not supported.

        :return: An initialized ``IPAServerCA`` object.
        :rtype: SCAutolib.models.CA.IPAServerCA
        :raises SCAutolibIPAException: If the IPA server CA dump file is not
                                       found or if the loaded object is not a
                                       valid ``IPAServerCA`` instance.
        """
        json_file = LIB_DUMP_CAS.joinpath("ipa-server.json")
        if not json_file.exists():
            msg = "Dump file for ipa server CA is not present."
            logger.error(msg)
            logger.error("The reason for this is most likely that the system "
                         "was not configured for IPA client via SCAutolib")
            raise SCAutolibIPAException(msg)
        ca = BaseCA.load(json_file)
        if not isinstance(ca, IPAServerCA):
            msg = "Values in dump file are not valid for IPA server, so the " \
                "object can't be created"
            logger.error(msg)
            raise SCAutolibIPAException(msg)
        return ca
