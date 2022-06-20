import os
import paramiko
from cryptography import x509
from fabric.connection import Connection
from hashlib import md5
from invoke import Responder
from pathlib import Path
from python_freeipa import exceptions
from python_freeipa.client_meta import ClientMeta
from shutil import rmtree, copy
from socket import gethostname

# from SCAutolib.models.user import IPAUser
from SCAutolib import TEMPLATES_DIR, logger, run, LIB_DIR
from SCAutolib.exceptions import SCAutolibException


class CA:

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
        """
        ...

    def setup(self, force: bool = False):
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


class LocalCA(CA):
    template = Path(TEMPLATES_DIR, "ca.cnf")

    def __init__(self, root_dir: Path = Path("/etc/SCAutolib/ca")):
        """
        Class for local CA. Initialize required attributes, real setup is made
        by LocalCA.setup() method

        :param root_dir: Path to root directory of the CA. By default, is in
                         /etc/SCAutolib/ca
        :type: Path
        """
        self.root_dir: Path = root_dir
        self._conf_dir: Path = Path(root_dir, "conf")
        self._newcerts: Path = Path(root_dir, "newcerts")
        self._certs: Path = Path(root_dir, "certs")
        self._crl: Path = Path(root_dir, "crl", "root.pem")
        self._ca_pki_db: Path = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")

        self._ca_cnf: Path = Path(self._conf_dir, "ca.cnf")
        self._ca_cert: Path = Path(root_dir, "rootCA.pem")
        self._ca_key: Path = Path(root_dir, "rootCA.key")

        self._serial: Path = Path(root_dir, "serial")
        self._index: Path = Path(root_dir, "index.txt")

    def setup(self, force: bool = False):
        """
        Creates directory and file structure needed by local CA. If directory
        already exists and force = True, directory would be recursively deleted
        and new local CA would be created. Otherwise, configuration would be
        skipped.

        :param force: overwrite existing configuration with force if True,
                      otherwise, skip configuration.
        :type force: bool
        """
        if self.root_dir.exists():
            logger.warning(f"Directory {self.root_dir} already exists.")
            if not force:
                logger.warning("Skipping configuration.")
                return

            self.cleanup()

        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._ca_cnf.parent.mkdir()
        self._newcerts.mkdir()
        self._certs.mkdir()
        self._crl.parent.mkdir()

        # Copy template and edit it with current root dir for CA
        copy(self.template, self._ca_cnf)
        with self._ca_cnf.open("r+") as f:
            f.write(f.read().format(ROOT_DIR=self.root_dir))
        with self._serial.open("w") as f:
            f.write("01")

        self._index.touch()

        # Generate self-signed certificate
        cmd = ['openssl', 'req', '-batch', '-config', self._ca_cnf,
               '-x509', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout',
               self._ca_key, '-sha256', '-set_serial', '0',
               '-extensions', 'v3_ca', '-out', self._ca_cert]
        run(cmd, check=True)
        logger.info(f"CA private key is generated into {self._ca_key}")
        logger.info(
            f"CA self-signed certificate is generated into {self._ca_cert}")

        # Configuring CRL
        run(['openssl', 'ca', '-config', self._ca_cnf, '-gencrl',
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
            elif cert_out.is_file():
                cert_out = cert_out.with_suffix(".pem")
        else:
            cert_out = self._certs.joinpath(f"{username}.pem")
        cmd = ["openssl", "ca", "-config", self._ca_cnf,
               "-batch", "-keyfile", self._ca_key, "-in", csr,
               "-notext", "-days", "365", "-extensions", "usr_cert",
               "-out", cert_out]
        run(cmd, check=True)
        return cert_out

    def revoke_cert(self, cert: Path):
        """
        Revoke given certificate

        :param cert: path to the certificate
        :type cert: pathlib.Path
        """
        cmd = ['openssl', 'ca', '-config', self._ca_cnf, '-revoke', cert]
        run(cmd, check=True)
        cmd = ['openssl', 'ca', '-config', self._ca_cnf, '-gencrl',
               '-out', self._crl]
        run(cmd, check=True)
        logger.info("Certificate is revoked")

    def cleanup(self):
        """
        Remove the root directory of the CA
        """
        logger.warning(f"Removing local CA {self.root_dir}")
        rmtree(self.root_dir, ignore_errors=True)
        logger.info(f"Local CA from {self.root_dir} is removed")


class IPAServerCA(CA):
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

    _ipa_server_ip: str = None
    _ipa_server_hostname: str = None
    _ipa_server_domain: str = None
    _ipa_server_admin_passwd: str = None
    _ipa_server_realm: str = None
    _ipa_client_hostname: str = None
    _ipa_server_root_passwd: str = None
    meta_client: ClientMeta = None

    def __init__(self, ip_addr: str, hostname: str, domain: str,
                 admin_passwd: str, root_passwd: str, client_hostname: str,
                 realm: str = None):
        """
        Initialize object for IPA client for given IPA server. Also, creates
        meta client (python_freeipa.client_meta.ClientMeta) logged in to the
        server and ready-to-use.

        :param ip_addr: IP address of the IPA server
        :type ip_addr: str
        :param hostname: Hostname of the IPA server
        :type hostname: str
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
        self._ipa_server_hostname = hostname
        self._add_to_hosts()  # So we can log in to the IPA before setup

        self._ipa_server_domain = domain
        self._ipa_server_admin_passwd = admin_passwd
        self._ipa_server_realm = realm if realm is not None else domain.upper()
        self._ipa_client_hostname = client_hostname
        self._ipa_server_root_passwd = root_passwd
        self.meta_client: ClientMeta = ClientMeta(self._ipa_server_hostname,
                                                  verify_ssl=False)
        self.meta_client.login("admin", self._ipa_server_admin_passwd)

    def setup(self, force: bool = False):
        """
        Setup IPA client for IPA server. After IPA client is installed, system
        would be configured for smart card login with IPA using script from
        IPA server obtained via SSH.

        :param force: if True, previous installation of the IPA client would be
            removed
        :type force: bool
        """

        if self.is_installed:
            logger.warning("IPA client is already configured on this system.")
            if not force:
                logger.info("Set force argument to True if you want to remove "
                            "previous installation.")
                return
            self.restore()

        logger.info(f"Start setup of IPA client on the system for "
                    f"{self._ipa_server_hostname} IPA server.")

        self._add_to_resolv()
        self._set_hostname()

        run(["ipa-client-install", "-p", "admin",
             "--password", self._ipa_server_admin_passwd,
             "--server", self._ipa_server_hostname,
             "--domain", self._ipa_server_domain,
             "--realm", self._ipa_server_realm,
             "--hostname", self._ipa_client_hostname,
             "--all-ip-addresses", "--force", "--force-join", "--no-ntp", "-U"],
            input="yes")
        logger.debug("IPA client is installed")

        ipa_client_script = self._get_sc_setup_script()
        run(f'bash {ipa_client_script} /etc/ipa/ca.crt', check=True)
        logger.debug("Setup of IPA client for smart card is finished")

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

    @property
    def is_installed(self):
        """
        :return: True, if IPA client is installed on the system (ipa command
            returns zero return code), otherwise False
        :rtype: bool
        """
        out = run(["ipa", "help"], print_=False, check=False)
        return out.returncode == 0

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
        with open("/etc/resolv.conf", "w+") as f:
            cnt = f.read()
            if nameserver not in cnt:
                logger.warning(f"Nameserver {self._ipa_server_ip} is not "
                               "present in /etc/resolve.conf. Adding...")
                f.write(nameserver + "\n" + cnt)
                logger.info(
                    "IPA server is added to /etc/resolv.conf "
                    "as first nameserver")
                run("chattr -i /etc/resolv.conf")
                logger.info("File /etc/resolv.conf is blocked for editing")

    def _add_to_hosts(self):
        """
        Add IPA server (IP address and hostname) to /etc/hosts
        """
        entry = f"{self._ipa_server_ip} {self._ipa_server_hostname}"
        with open("/etc/hosts", "r+") as f:
            cnt = f.read()
            if entry not in cnt:
                f.write(entry)
                logger.warning(
                    f"New entry {entry} for IPA server is added to /etc/hosts")
            logger.info(
                f"Entry for IPA server {entry} presents in the /etc/hosts")

    def _get_sc_setup_script(self) -> Path:
        """
        Fetch script for smart card setup of IPA client. Script is generated
        only on IPA server. Fetching is made by connecting to the host via SSH.

        :return: Path to script
        :rtype: patlib.Path
        """
        ipa_client_script = Path(LIB_DIR, "ipa-client-sc.sh")
        kinitpass = Responder(pattern="Password for admin@SC.TEST.COM: ",
                              response=f"{self._ipa_server_admin_passwd}\n")
        with Connection(self._ipa_server_ip, user="root",
                        connect_kwargs={"password":
                                        self._ipa_server_root_passwd}) as c:
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
            c.run("kinit admin", pty=True, watchers=[kinitpass], in_stream=False)
            result = c.run("ipa-advise config-client-for-smart-card-auth",
                           hide=True, in_stream=False)
            with open(ipa_client_script, "w") as f:
                f.write(result.stdout)
        if os.stat(ipa_client_script).st_size == 0:
            msg = "Script for IPA client smart card setup is not correctly " \
                  "copied to the host"
            logger.error(result.stdout)
            logger.error(result.stderr)
            raise SCAutolibException(msg)
        logger.debug("File for setting up IPA client for smart cards is "
                     f"copied to {ipa_client_script}")
        return ipa_client_script

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

    def restore(self):
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
        run(["ipa-client-install", "--uninstall", "-U"], check=True)
        logger.info("IPA client is removed.")

    class __PKeyChild(paramiko.PKey):
        """This child class is need to fix SSH connection with MD5 algorithm
        in FIPS mode

        This is just workaround until PR in paramiko would be accepted
        https://github.com/paramiko/paramiko/issues/396. After this PR is merged,
        delete this class
        """

        def get_fingerprint_improved(self):
            return md5(self.asbytes(), usedforsecurity=False).digest()
