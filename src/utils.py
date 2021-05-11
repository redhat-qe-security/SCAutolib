import datetime
import subprocess as subp
from os import path, remove
from random import randint
from time import sleep
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from shutil import copy

import virt_card as virt_sc
import authselect as authselect
from env import check_env
from SCAutolib import env_logger, log

DIR_PATH = path.realpath(path.dirname(path.abspath(__file__)))
SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
# DEFAULTS = {"sssd": f"{DIR_PATH}/env/conf/sssd.conf"}  # FIXME: fix default path
TMP = None
KEYS = None
CERTS = None
BACKUP = None


def edit_config(service: str, string: str, holder: str, section: bool = True):
    """
    Decorator for editing config file. Before editing, config file is backuped.

    :param service: service for which config file will be edited
    :param string: string to add or replace
    :param holder: what is need to be replace. In case of adding the string to
                   the file, specify section where string should be added
    :param section: specify if holder is a name of a section in the config file
    :return: decorated function
    """

    def wrapper(test):
        @backup(SERVICES[service], service)
        def inner_wrapper(*args, **kwargs):
            _edit_config(SERVICES[service], string, holder, section)
            restart_service(service)
            test(*args, **kwargs)

        return inner_wrapper

    return wrapper


def backup(file_path: str, service: str = None):
    """
    Decorator for backingup file. After executing wrapped function, restore
    given file to the prevrious location.

    :param file_path: path to file to be backuped
    :param service: service to be restarted after restoring the file.
                    By default is None - no service is need to be restarted
    :return: decorated function
    """

    def wrapper(test):
        def inner_wrapper(*args, **kwargs):
            _backup(file_path=file_path, service=service, fnc=test, *args, **kwargs)

        return inner_wrapper

    return wrapper


@check_env()
def _backup(file_path, name=None, service=None, fnc=None, *args, **kwargs):
    # Compose target file. If 'name' is specified, file would have this name,
    # otherwise the name would remain is in the source
    target = f"{BACKUP}/{path.split(file_path)[1] if name is None else name}"

    copy(file_path, target)
    log.debug(f"File from {file_path} is copied to {target}")

    if fnc is not None:
        try:
            fnc(*args, **kwargs)
        except Exception as e:
            raise e
        finally:
            copy(target, file_path)
            log.debug(f"File from {target} is restored to {file_path}")
            remove(target)
            if service is not None:
                restart_service(service)


def _edit_config(config: str, string: str, holder: str, section: bool):
    """
    Funcion for actual editing the config file.

    :param config: path to config file
    :param string: string to be add
    :param holder: section or substinrg to update
    :param section: specify if holder is a section
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

    :param service: service name
    :return: return code of systemcrt restart
    """
    try:
        result = subp.run(["systemctl", "restart", f"{service}"], check=True, encoding="utf8")
        sleep(5)
        log.debug(f"Service {service} is restarted")
        return result.returncode
    except subp.CalledProcessError as e:
        log.error(f"Command {' '.join(e.cmd)} is ended with non-zero return code ({e.returncode})")
        log.error(f"stdout:\n{e.stdout}")
        log.error(f"stderr:\n{e.stderr}")
        return e.returncode


@check_env()
def generate_root_ca_crt():
    """
    Function for generating the root CA certificate with keys

    :return: tuple with path to the certificate and to the key files.
    """
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

    :param pin: Specif is PIN or password is used for login
    :param passwd: PIN or password for login
    :param username: username to login
    """
    with authselect.Authselect():
        with virt_sc.VirtCard(insert=True) as sc:
            sc.run_cmd(f'su - {username} -c "su - {username} -c whoami"',
                       expect=username, passwd=passwd, pin=pin)
