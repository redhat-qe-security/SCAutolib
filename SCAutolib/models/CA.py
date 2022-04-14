from pathlib import Path
from shutil import rmtree, copy

from SCAutolib import TEMPLATES_DIR, run, logger


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
                cert_out.rename(cert_out.with_suffix(".pem"))
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
