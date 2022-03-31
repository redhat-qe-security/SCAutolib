from .ca import CA
from pathlib import Path
from shutil import rmtree, copy
from SCAutolib import logger
from SCAutolib.src import TEMPLATES_DIR, run


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
        self._crl: Path = Path(root_dir, "crl", "root.crl")
        self._ca_pki_db: Path = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")

        self._ca_cnf = Path(self._conf_dir, "ca.cnf")
        self._ca_cert = Path(root_dir, "rootCA.pem")
        self._ca_key = Path(root_dir, "rootCA.key")

        self._serial = Path(root_dir, "serial")
        self._index = Path(root_dir, "index.txt")

    def setup(self, force: bool = False):
        """
        Creates directory and file structure needed by local CA. If directory
        already exists and force = True, directory would be recursively deleted
        and new local CA would be created. Otherwise, configuration would be
        skipped.

        :param force: overwrite existing configuration with force if True,
                      otherwise, skip configuration.
        """
        if self.root_dir.exists():
            logger.warning(f"Directory {self.root_dir} already exists.")
            if not force:
                logger.warning("Skipping configuration.")
                return
            logger.warning("Removing configuration.")
            rmtree(self.root_dir)

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
        run(['openssl', 'req', '-batch', '-config', self._ca_cnf,
             '-x509', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout',
             self._ca_key, '-sha256', '-set_serial', '0',
             '-extensions', 'v3_ca', '-out', self._ca_cert])
        logger.info(f"CA private key is generated into {self._ca_key}")
        logger.info(
            f"CA self-signed certificate is generated into {self._ca_cert}")

        # Configuring CRL
        run(['openssl', 'ca', '-config', self._ca_cnf, '-gencrl',
             '-out', self._crl])

        with self._ca_cert.open("r") as f_cert:
            root_cert = f_cert.read()

        if self._ca_pki_db.exists():
            # Check if current CA cert doesn't present in the sssd auth db
            with self._ca_pki_db.open("r") as f:
                data = f.read()
            if root_cert not in data:
                with self._ca_pki_db.open("a") as f:
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
        :param username: subject in the CSR
        :param cert_out: path where the certificate should be duplicated.
                         Default None

        :return: returns path to the signed certificate
        """
        if cert_out is not None:
            if cert_out.is_dir():
                cert_out = cert_out.joinpath(f"{username}.pem")
            elif cert_out.is_file():
                cert_out.rename(cert_out.with_suffix(".pem"))
        else:
            cert_out = Path(self._certs, f"{username}.pem")

        run(["openssl", "ca", "-config", self._ca_cnf,
             "-batch", "-keyfile", self._ca_key, "-in", csr,
             "-notext", "-days", "365", "-extensions", "usr_cert",
             "-out", cert_out])
        return cert_out

    def revoke_cert(self, cert: Path):
        """
        Revoke given certificate

        :param cert: path to the certificate
        """
        cmd = ['openssl', 'ca', '-config', self._ca_cnf, '-revoke', cert]
        run(cmd, check=True)
        logger.info("Certificate is revoked")

    def restore(self):
        logger.debug("Removing local CA")
        rmtree(self.root_dir, ignore_errors=True)
        logger.info(f"Local CA from {self.root_dir} is removed")
