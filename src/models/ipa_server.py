from hashlib import md5
from pathlib import Path

from SCAutolib import logger
from SCAutolib.src import run, LIB_DIR
from SCAutolib.src.models.sssd_conf import SSSDConf
from fabric.connection import Connection
from invoke import Responder

from .ca import CA


class IPAServerCA(CA):
    _ipa_server_ip: str = None
    _ipa_server_hostname: str = None
    _ipa_server_domain: str = None
    _ipa_server_admin_passwd: str = None
    _ipa_server_realm: str = None
    _ipa_client_hostname: str = None
    _ipa_server_root_passwd: str = None

    def __init__(self, ip_addr: str, hostname: str, domain: str,
                 admin_passwd: str, root_passwd: str, client_hostname: str,
                 realm: str = None):
        self._ipa_server_ip = ip_addr
        self._ipa_server_domain = domain
        self._ipa_server_hostname = hostname
        self._ipa_server_admin_passwd = admin_passwd
        self._ipa_server_realm = realm if realm is not None else domain.upper()
        self._ipa_client_hostname = client_hostname
        self._ipa_server_root_passwd = root_passwd

    def setup(self, force: bool = False, paramiko=None):
        logger.info(f"Start setup of IPA client on the system for "
                    f"{self._ipa_server_hostname} IPA server.")

        entry = f"{self._ipa_server_ip} {self._ipa_server_hostname}"
        nameserver = f"nameserver {self._ipa_server_ip}"
        ipa_client_script = Path(LIB_DIR, "ipa-client-sc.sh")

        with open("/etc/hosts", "r+") as f:
            cnt = f.read()
            if entry not in cnt:
                f.write(entry)
                logger.warning(
                    f"New entry {entry} for IPA server is added to /etc/hosts")
            logger.info(
                f"Entry for IPA server {entry} presents in the /etc/hosts")

        with open("/etc/resolv.conf", "w+") as f:
            cnt = f.read()
            if nameserver not in cnt:
                logger.warning(f"Nameserver {self._ipa_server_ip} is not present in "
                               f"/etc/resolve.conf. Adding...")
                f.write(nameserver + "\n" + cnt)
                logger.info(
                    "IPA server is added to /etc/resolv.conf as first nameserver")
                run("chattr -i /etc/resolv.conf")
                logger.info("File /etc/resolv.conf is blocked for editing")

        run(f"hostnamectl set-hostname {self._ipa_client_hostname} --static")
        logger.debug(f"Hostname is set to {self._ipa_client_hostname}")

        run(["ipa-client-install", "-p", "admin",
             "--password", self._ipa_server_admin_passwd,
             "--server", self._ipa_server_hostname,
             "--domain", self._ipa_server_domain,
             "--realm", self._ipa_server_realm,
             "--hostname", self._ipa_client_hostname,
             "--all-ip-addresses", "--force", "--force-join", "--no-ntp", "-U"],
            input="yes")
        logger.debug("IPA client is installed")

        SSSDConf.set(key="certificate_verification", value="no_ocsp",
                     section="sssd")
        run("systemctl restart sssd")  # FIXME: restart service with internal call

        run("kinit admin", input=self._ipa_server_admin_passwd)
        logger.debug("Kerberos ticket for admin user is obtained")

        kinitpass = Responder(pattern="Password for admin@SC.TEST.COM: ",
                              response="SECret.123\n")
        with Connection(self._ipa_server_ip, user="root",
                        connect_kwargs=
                            {"password": self._ipa_server_root_passwd}) as c:
            # Delete this block when PR in paramiko will be accepted
            # https://github.com/paramiko/paramiko/issues/396
            #### noqa:E266
            paramiko.PKey.get_fingerprint = self.__PKeyChild.get_fingerprint_improved
            c.client = paramiko.SSHClient()
            c.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            #### noqa:E266
            c.open()
            c.run("kinit admin", pty=True, watchers=[kinitpass])
            result = c.run("ipa-advise config-client-for-smart-card-auth")
            with open(ipa_client_script, "w") as f:
                f.write(result.stdout)

    def request_cert(self, csr: Path, username: str):
        """Request certificate from the IPA server for given username"""

    def revoke_cert(self, cert: Path):
        ...

    def remove(self):
        ...

    class __PKeyChild(paramiko.PKey):
        """This child class is need to fix SSH connection with MD5 algorith
        in FIPS mode

        This is just workaround until PR in paramiko would be accepted
        https://github.com/paramiko/paramiko/issues/396. After this PR is merged,
        delete this class
        """

        def get_fingerprint_improved(self):
            return md5(self.asbytes(), usedforsecurity=False).digest()
