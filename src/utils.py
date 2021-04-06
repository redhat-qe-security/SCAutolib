import datetime
import subprocess as subp
from os import path, mkdir, remove
from random import randint
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from shutil import copy
from SCAutolib import log

DIR_PATH = path.dirname(path.abspath(__file__))
SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
DEFAULTS = {"sssd": f"{DIR_PATH}/env/conf/sssd.conf"}
TMP = f"{DIR_PATH}/tmp"
KEYS = f"{TMP}/keys"
CERTS = f"{TMP}/certs"
BACKUP = f"{TMP}/backup"


def edit_config(service, string, section):
    def wrapper(test):
        def inner_wrapper(*args):
            _edit_config(SERVICES[service], string, section)
            restart_service(service)
            test(args)
            restore_config(service)
            restart_service(service)

        return inner_wrapper

    return wrapper


def backup(file_path, service=None):
    def wrapper(test):
        def inner_wrapper(*args):
            if not path.exists(BACKUP):
                mkdir(BACKUP)
            target = f"{BACKUP}/{path.split(file_path)[1]}-backup"
            copy(file_path, target)
            log.debug(f"File from {file_path} is copied to {target}")
            if service is not None:
                restart_service(service)
            test(args)
            copy(target, file_path)
            log.debug(f"File from {target} is restored to {file_path}")
            remove(file_path)
            if service is not None:
                restart_service(service)

        return inner_wrapper

    return wrapper


def _edit_config(config, string, section):
    holder = f"#<{section}>"
    with open(config, "r") as file:
        content = file.read()
        if holder not in content:
            log.error(f"File {config} is not updated. "
                      f"Maybe placeholder in the config {config} "
                      f"for the section {section} is missing?")
            raise Exception(f"Placeholder {holder} is not present in {config}")

    content = content.replace(holder, f"{string}\n{holder}")
    with open(config, "w+") as file:
        file.write(content)

    log.debug(f"Section {section} if config file {config} is updated")


def restart_service(service):
    try:
        subp.run(["systemctl", "restart", f"{service}"], check=True, encoding="utf8")
        log.debug(f"Service {service} is restarted")
    except subp.CalledProcessError as e:
        log.error(f"Command {e.cmd} is ended with non-zero return code ({e.returncode})")
        log.error(f"stdout:\n{e.stdout}")
        log.error(f"stderr:\n{e.stderr}")
    except Exception as e:
        log.error(f"Unexpected exception is raised: {e}")
        raise e


def restore_config(service=None):
    try:
        shutil.copyfile(DEFAULTS[service], SERVICES[service])
        log.debug(f"File {SERVICES[service]} is restored")
    except shutil.SameFileError:
        log.debug(f"Source file {DEFAULTS[service]} and destination file {SERVICES[service]} are the same")
    except Exception as e:
        log.error(f"Unexpected exception is raised: {e}")
        log.error(f"File {SERVICES[service]} is not restored")
        raise e


def generate_root_ca_crt(issuer="Example"):
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
