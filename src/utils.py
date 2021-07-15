import datetime
import subprocess as subp
from os import path
from random import randint
from time import sleep
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from shutil import copy
from decouple import config

import SCAutolib.src.virt_card as virt_sc
import SCAutolib.src.authselect as authselect
from SCAutolib import env_logger, log

DIR_PATH = path.realpath(path.dirname(path.abspath(__file__)))
SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
TMP = None
KEYS = None
CERTS = None
BACKUP = None


def check_env():
    """
    Insure that environment variables are loaded from .env file.
    """
    global BACKUP
    global KEYS
    global CERTS
    global TMP
    if BACKUP is None:
        BACKUP = config("BACKUP")
    if KEYS is None:
        KEYS = config("KEYS")
    if CERTS is None:
        CERTS = config("CERTS")
    if TMP is None:
        CERTS = config("TMP")


def edit_config(service: str, string: str, holder: str, section: bool = True):
    """
    Decorator for editing config file. Before editing, config file is backuped.

    Args:
        service: service for which config file will be edited
        string: string to add or replace
        holder: what is need to be replace. In case of adding the string to
                the file, specify section where string should be added
                section: specify if holder is a name of a section in the config file
        section: specifies if holder is a section or a substring in the file

    Returns:
        decorated function
    """

    def wrapper(test):
        @backup(SERVICES[service], service, restore=True)
        def inner_wrapper(*args, **kwargs):
            _edit_config(SERVICES[service], string, holder, section)
            restart_service(service)
            test(*args, **kwargs)

        return inner_wrapper

    return wrapper


def backup(file_path: str, service: str = None, name: str = None, restore=True):
    """
    Decorator for backup the file into BACKUP directory. Can restor the file
    after execution of function and restart given service.

    Args:
        file_path: path to file to be backuped
        service: service to be restarted after restoring the file.
                 By default is None - no service is need to be
                 restarted (optional).
        name: name for backup file (optional)
        restore: specifies if given file should be restored after function execution

    Returns:
        decorated function
    """
    if name is None:
        # if no name is given, than original name of the file would be used
        name = path.split(file_path)[1]

    def wrapper(test):
        def inner_wrapper(*args, **kwargs):
            _backup(file_path=file_path, name=name)
            test(*args, **kwargs)
            if restore:
                _restore_file(target=file_path, name=name, service=service)
                restart_service(service)
        return inner_wrapper

    return wrapper


def _restore_file(target, name, service=None):
    """
    Restoring file from BACKUP directory to target. Target has to be a file.

    Args:
        target: target path
        name: name of the file in BACKUP directory
        service: service which should be restarted after file is restored.
                 By default is None (no need to restart any services).
    """
    check_env()
    source = path.join(BACKUP, name)
    copy(source, target)
    subp.run(["restorecon", "-v", target])
    restart_service(service)
    log.debug(f"File from {source} is restored to {target}")


def _backup(file_path, name=None):
    """
    Backup the file given in file_path to BACKUP directory.

    Args:
        file_path: path to fle
        name: file name in BACKUP directory
    """
    check_env()
    target = f"{BACKUP}/{name}"
    copy(file_path, target)

    log.debug(f"File from {file_path} is copied to {target}")


def _edit_config(config: str, string: str, holder: str, section: bool):
    """
    Funcion for actual editing the config file.

    Args:
        config: path to config file
        string: string to be add
        holder: section or substinrg to update
        section: specify if holder is a section
    """
    old = f"#<[{holder}]>" if section else holder
    new = f"{string}\n{old}" if section else string

    with open(config, "r") as file:
        content = file.read()
        if (old is not None) and (old not in content):
            log.error(f"File {config} is not updated. "
                      f"Maybe placeholder in the config {config} "
                      f"for the section {holder} is missing?")
            raise Exception(f"Placeholder {old} is not present in {config}")

    content = content.replace(old, new)
    with open(config, "w+") as file:
        file.write(content)

    log.debug(f"{'Section' if section else 'Substring'} {holder} in config "
              f"file {config} is updated")


def restart_service(service: str) -> int:
    """
    Restart given service and wait 5 sec

    Args:
        service: service name

    Returns:
        return code of systemcrt restart
    """
    if service is not None:
        try:
            result = subp.run(["systemctl", "restart", f"{service}"], check=True, encoding="utf8")
            sleep(5)
            env_logger.debug(f"Service {service} is restarted")
            return result.returncode
        except subp.CalledProcessError as e:
            env_logger.error(f"Command {' '.join(e.cmd)} is ended with non-zero return code ({e.returncode})")
            env_logger.error(f"stdout:\n{e.stdout}")
            env_logger.error(f"stderr:\n{e.stderr}")
            return e.returncode
    return 0


def generate_root_ca_crt():
    """
    Function for generating the root CA certificate with keys

    Returns:
        tuple with path to the certificate and to the key files.
    """
    check_env()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = randint(1, 1000)

    key_path = f"{KEYS}/private-key-{serial}.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Example-{serial}"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Example-{serial} Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Example-{serial} Test Ca"),
    ])

    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
    key_usage = x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False,
        decipher_only=False)

    subject_key = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key)

    builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(serial) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .add_extension(basic_constraints, critical=True) \
        .add_extension(key_usage, critical=True) \
        .add_extension(subject_key, critical=True) \
        .add_extension(authority_key, critical=True) \
        .sign(key, hashes.SHA256())
    cert = f"{CERTS}/rootCA-{serial}.pem"
    with open(cert, "wb") as f:
        f.write(builder.public_bytes(serialization.Encoding.PEM))

    return cert, key_path


def check_su_login_with_sc(pin=True, passwd="123456", username="localuser1"):
    """
    Function for common use case - su loging.

    Args:
        pin: Specif is PIN or password is used for login
        passwd: PIN or password for login
        username: username to login
    """
    with authselect.Authselect():
        with virt_sc.VirtCard(insert=True) as sc:
            sc.run_cmd(f'su - {username} -c "su - {username} -c whoami"',
                       expect=username, passwd=passwd, pin=pin)
