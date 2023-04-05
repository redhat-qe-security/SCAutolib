"""
This module implements classes that represents Certification Authorities (CA).
"""
import shutil

import re

import json
import os
import python_freeipa
from cryptography import x509
from hashlib import md5
from pathlib import Path, PosixPath
from python_freeipa import exceptions
from python_freeipa.client_meta import ClientMeta
from shutil import rmtree, copy2
from socket import gethostname

from SCAutolib import TEMPLATES_DIR, logger, run, LIB_DIR, LIB_DUMP_CAS
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models.file import OpensslCnf


class BaseCA:
    dump_file: Path = None
    _ca_cert: Path = None
    _ca_key: Path = None

    @property
    def cert(self):
        return self._ca_cert

    def request_cert(self, csr, username: str, cert_out: Path):
        """
        Request certificate from CA for given username

        :param csr: path to CSR
        :type csr: str
        :param username: subject for the certificate
        :type username: str
        :param cert_out: path where the certificate should be duplicated.
            Default None
        :type cert_out: pathlib.Path
        :return: None or path where the certificate is stored.
        :rtype: None or pathlib.Path
        """
        ...

    def setup(self):
        """
        Configure the CA

        :param force: In case if CA is already configured, specifies if it
            should be reconfigured with force
        :type force: bool
        """
        ...

    def sign_cert(self):
        """
        Sign the certificate
        """
        ...

    def revoke_cert(self, cert: Path):
        """
        Revoke the certificate

        :param cert:
        :type cert: pathlib.Path
        """
        ...

    @staticmethod
    def load(json_file):
        """
        Load CA from JSON file.
        :return: CA object
        """
        with json_file.open("r") as f:
            cnt = json.load(f)

        if "_ipa_server_ip" in cnt.keys():
            ca = IPAServerCA(ip_addr=cnt["_ipa_server_ip"],
                             server_hostname=cnt["_ipa_server_hostname"],
                             root_passwd=cnt["_ipa_server_root_passwd"],
                             admin_passwd=cnt["_ipa_server_admin_passwd"],
                             client_hostname=cnt["_ipa_client_hostname"],
                             domain=cnt["_ipa_server_domain"],
                             realm=cnt["_ipa_server_realm"])
        else:
            ca = LocalCA(root_dir=cnt["root_dir"])
        logger.debug(f"CA {type(ca)} is restored from file {json_file}")
        return ca


class LocalCA(BaseCA):
    template = Path(TEMPLATES_DIR, "ca.cnf")
    dump_file = LIB_DUMP_CAS.joinpath("local-ca.json")

    def __init__(self, root_dir: Path = None, cnf: OpensslCnf = None):
        """
        Class for local CA. Initialize required attributes, real setup is made
        by LocalCA.setup() method

        :param root_dir: Path to root directory of the CA. By default, is in
            /etc/SCAutolib/ca
        :type: Path
        """
        self.root_dir: Path = Path("/etc/SCAutolib/ca") if root_dir is None \
            else root_dir
        assert self.root_dir is not None
        self._conf_dir: Path = self.root_dir.joinpath("conf")
        self._newcerts: Path = self.root_dir.joinpath("newcerts")
        self._certs: Path = self.root_dir.joinpath("certs")
        self._crl: Path = self.root_dir.joinpath("crl", "root.pem")
        self._ca_pki_db: Path = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")

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
        return self._ca_cnf

    @cnf.setter
    def cnf(self, cnf: OpensslCnf):
        if not cnf.path.exists():
            raise SCAutolibException("CNF file does not exist")
        self._ca_cnf = cnf

    def to_dict(self):
        """
        Customising default property for better serialisation for storing to
        JSON format.

        :return: dictionary with all values. Path objects are typed to string.
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
        Check if the local CA is installed
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
        Creates directory and file structure needed by local CA. If directory
        already exists and force = True, directory would be recursively deleted
        and new local CA would be created. Otherwise, configuration would be
        skipped.
        """
        if self._ca_cnf is None:
            raise SCAutolibException("CA CNF file is not set")
        elif not self._ca_cnf.path.exists():
            raise SCAutolibException("CA CNF does not exist")

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

        with self._ca_cert.open("r") as f_cert:
            root_cert = f_cert.read()

        if self._ca_pki_db.exists():
            # Check if current CA cert doesn't present in the sssd auth db
            with self._ca_pki_db.open("a+") as f:
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

        logger.info("Local CA is configured")

    def request_cert(self, csr: Path, username: str,
                     cert_out: Path = None) -> Path:
        """
        Create the certificate from CSR and sign it. Certificate is store
        in the <root ca directory>/ca/newcerts directory with name username.pem

        :param csr: path to CSR
        :type csr: pathlib.Path
        :param username: subject in the CSR
        :type username: str
        :param cert_out: path where the certificate should be duplicated.
                         Can be a directory or a file. If a file, .pem extension
                         would be set to the filename. If not specified,
                         certificate would be created in default directory and
                         filename  <root ca directory>/certs/<username>.pem
        :type cert_out: pathlib.Path
        :return: returns path to the signed certificate
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
        Revoke given certificate

        :param cert: path to the certificate
        :type cert: pathlib.Path
        """
        cmd = ['openssl', 'ca', '-config', self._ca_cnf.path, '-revoke', cert]
        run(cmd, check=True)
        cmd = ['openssl', 'ca', '-config', self._ca_cnf.path, '-gencrl',
               '-out', self._crl]
        run(cmd, check=True)
        logger.info("Certificate is revoked")

    def cleanup(self):
        """
        Remove the root directory of the CA
        """
        logger.warning(f"Removing local CA {self.root_dir}")
        for file in self.root_dir.iterdir():
            if file.is_file():
                file.unlink()
            elif file.is_dir():
                shutil.rmtree(file)
        logger.info(f"Local CA from {self.root_dir} is removed")


class IPAServerCA(BaseCA):
    """
    Class represents IPA server with integrated CA. Through this class
    communication with IPA server is made primarily using
    ``python_freeipa.client_meta.ClientMeta`` class.

    During setup of the IPA client
    on the system, script generated on IPA server side has to be executed for
    setting up the client for smart card authentication. For this reason SSH
    connection is made to the server and the script is fetched in frame of
    ``IPAServerCA.create()`` method.
    """

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
        Initialize object for IPA client for given IPA server. Also, creates
        meta client (python_freeipa.client_meta.ClientMeta) logged in to the
        server and ready-to-use.

        :param ip_addr: IP address of the IPA server
        :type ip_addr: str
        :param server_hostname: Hostname of the IPA server
        :type server_hostname: str
        :param domain: Domain name of the IPA server
        :type domain: str
        :param admin_passwd: Password for admin user on the IPA server
        :type admin_passwd: str
        :param root_passwd: Password for root user on the IPA server
                            (system user)
        :type root_passwd: str
        :param client_hostname: Hostname for the client. This name would be set
                                on the client host
        :type client_hostname: str
        :param realm: Kerberos realm. If not set, domain in upper cases would
                      be used instead
        :type realm: str
        """
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
        :return: True, if IPA client is installed on the system (/etc/ipa
            directory contains ca.crt file from IPA server), otherwise False
        :rtype: bool
        """
        d = Path("/etc/ipa")
        result = d.exists()
        if result:
            result = d.joinpath("ca.crt")
        return result

    @property
    def domain(self):
        return self._ipa_server_domain

    def to_dict(self):
        """
        Customising default property for better serialisation for storing to
        JSON format.

        :return: dictionary with all values. Path objects are typed to string.
        :rtype: dict
        """
        dict_: dict = super().__dict__.copy()
        dict_.pop("meta_client")
        return dict_

    def setup(self):
        """
        Setup IPA client for IPA server. After IPA client is installed, system
        would be configured for smart card login with IPA using script from
        IPA server obtained via SSH.
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
            raise
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
            logger.debug("Maximum kerberos password lifetime is set to 365 days")

        # TODO: add to restore client host name
        logger.info("IPA client is configured on the system.")

    def _meta_client_login(self):
        """
        Login to admin user via IPA meta client.
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
        Set hostname for specified IPA client hostname
        """
        run(f"hostnamectl set-hostname {self._ipa_client_hostname} --static")
        logger.debug(f"Hostname is set to {self._ipa_client_hostname}")

    def _add_to_resolv(self):
        """
        Add new nameserver (IPA) to /etc/resolv.conf and lock this file for
        editing
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
            run("chattr -i /etc/resolv.conf")
            logger.info("File /etc/resolv.conf is blocked for editing")

        with open("/etc/resolv.conf", "r") as f:
            logger.debug(f"New resolv.conf\n{f.read()}")

    def _add_to_hosts(self):
        """
        Add IPA server (IP address and hostname) to /etc/hosts
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
        Fetch script for smart card setup of IPA client and place it to
        predefined location. Script is generated only on IPA server.
        Fetching is done by connecting to the host via SSH.
        """
        import paramiko
        from invoke import Responder
        from fabric.connection import Connection

        class __PKeyChild(paramiko.PKey):
            """This child class is need to fix SSH connection with MD5 algorithm
            in FIPS mode

            This is just workaround until PR in paramiko would be accepted
            https://github.com/paramiko/paramiko/issues/396. After this PR is
            merged, delete this class
            """

            def get_fingerprint_improved(self):
                return md5(self.asbytes(), usedforsecurity=False).digest()

        kinitpass = Responder(
            pattern=f"Password for admin@{self._ipa_server_realm}: ",
            response=f"{self._ipa_server_admin_passwd}\n")
        logger.debug("Start receiving client script for setting up smart card "
                     "on IPA client")
        with Connection(self._ipa_server_ip, user="root",
                        connect_kwargs={
                            "password": self._ipa_server_root_passwd}) as c:
            # Delete this block when PR in paramiko will be accepted
            # https://github.com/paramiko/paramiko/issues/396
            #### noqa:E266
            paramiko.PKey.get_fingerprint = \
                self.__PKeyChild.get_fingerprint_improved
            c.client = paramiko.SSHClient()
            c.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            #### noqa:E266
            c.open()
            # in_stream = False is required because while testing with pytest
            # it collision appears with capturing of the output.
            logger.debug("Running kinit on the IPA server")
            c.run("kinit admin", pty=True, watchers=[kinitpass], in_stream=False)
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
        Request certificate using CSR from IPA CA for given username. It is
        a wrapper around the python_freeipa.client_meta.ClientMeta.cert_request
        method. It works with a file, extracts CSR data from it and then
        stores in PEM format adding required prefix and suffix as in normal
        certificate and. If cert_out is a directory, then certificate would be
        stored in this directory with name <username>.pem. If it is a file,
        then check if it has PEM extension. If not, append .pem suffix to the
        name.

        :param csr: path to CSR
        :type csr: patlib.Path
        :param username: subject for the certificate
        :type username: str
        :param cert_out: path where the certificate is stored. Can be a
                         directory or a file.
        :type cert_out: patlib.Path

        :return: Path to the PEM certificate.
        :rtype: patlib.Path
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

    def add_user(self, user):
        """
        Add given user to IPA server. It is a wrapper on the
        python_freeipa.client_meta.ClientMeta.user_add method. Just extracts
        necessary fields from IPAUser object and pass them to the method. As a
        result, o_givenname == o_uid == o_sn == o_cn for simplicity.

        :param user: User to be added to the IPA server.
        """
        r = self.meta_client.user_add(user.username, user.username,
                                      user.username, user.username,
                                      o_userpassword=user.password)
        logger.debug(r)
        logger.info(f"User {user.username} is added to the IPA server")

    def del_user(self, user):
        """
        Remove user from IPA server.
        :param user: User to be deleted

        :raise AssertionError: If operation is failed. Fail is detected in
            return value from request to IPA server.
        """
        r = self.meta_client.user_del(user.username)["result"]
        logger.debug(r)
        logger.info(f"User {user.username} is removed from the IPA server")

    def revoke_cert(self, cert_path: Path):
        """
        Revoke given certificate on the IPA server. It is a wrapper on the
        python_freeipa.client_meta.ClientMeta.revoke_cert method. It extracts
        serial number of the certificate from the file

        :param cert_path: Path to the certificate in PEM format

        """
        with cert_path.open("rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        r = self.meta_client.cert_revoke(cert.serial_number)
        logger.debug(r)
        logger.info(f"Certificate {cert.serial_number} is revoked")
        return cert.serial_number

    def cleanup(self):
        """
        Remove IPA client from the system and from the IPA server

        :raise subprocess.CalledProcessError: by run function
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

    @property
    def ipa_server_hostname(self):
        return self._ipa_server_hostname
