import datetime
import subprocess as subp
from os import path, mkdir, remove
from random import randint
from time import sleep

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from shutil import copy, SameFileError, copyfile
from SCAutolib import log

DIR_PATH = path.dirname(path.abspath(__file__))
SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
DEFAULTS = {"sssd": f"{DIR_PATH}/env/conf/sssd.conf"}
TMP = f"{DIR_PATH}/tmp"
KEYS = f"{TMP}/keys"
CERTS = f"{TMP}/certs"
BACKUP = f"{TMP}/backup"


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
        def inner_wrapper(*args):
            _edit_config(SERVICES[service], string, holder, section)
            restart_service(service)
            test(args)

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
        def inner_wrapper(*args):
            if not path.exists(BACKUP):
                mkdir(BACKUP)
            target = f"{BACKUP}/{path.split(file_path)[1]}"
            copy(file_path, target)
            log.debug(f"File from {file_path} is copied to {target}")

            try:
                test(args)
            except Exception as e:
                raise e
            finally:
                copy(target, file_path)
                log.debug(f"File from {target} is restored to {file_path}")
                remove(target)
                if service is not None:
                    restart_service(service)

        return inner_wrapper

    return wrapper


def _edit_config(config: str, string: str, holder: str, section: bool):
    """
    Funcion for actual editing the config file.

    :param config: path to config file
    :param string: string to be add
    :param holder: section or substinrg to update
    :param section: specify if holder is a section
    """
    old = f"#<{holder}>" if section else holder
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

    log.debug(f"Section {holder} if config file {config} is updated")


def restart_service(service: str):
    """
    Restart given service and wait 5 sec

    :param service: service name
    """
    try:
        result = subp.run(["systemctl", "restart", f"{service}"], check=True, encoding="utf8")
        assert result.returncode == 0
        sleep(5)
        log.debug(f"Service {service} is restarted")
    except (subp.CalledProcessError, AssertionError) as e:
        log.error(f"Command {' '.join(e.cmd)} is ended with non-zero return code ({e.returncode})")
        log.error(f"stdout:\n{e.stdout}")
        log.error(f"stderr:\n{e.stderr}")
    except Exception as e:
        log.error(f"Unexpected exception is raised: {e}")
        raise e


def generate_root_ca_crt():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = randint(1, 1000)
    if not path.exists(TMP):
        mkdir(TMP)
        mkdir(KEYS)
        mkdir(CERTS)
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
