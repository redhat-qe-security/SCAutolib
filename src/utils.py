import datetime
import subprocess as subp
import sys
from os import environ, path
from os.path import isdir, isfile
from random import randint
from shutil import copy2, copytree
from time import sleep

import pexpect
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from decouple import UndefinedValueError, config
from SCAutolib import env_logger, log
from SCAutolib.src import DIR_PATH
from SCAutolib.src.exceptions import *

DOTNENV = f"{DIR_PATH}/.env"

SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
TMP = None
KEYS = None
CERTS = None
BACKUP: str = ""


def check_env():
    """
    Insure that environment variables are loaded from .env file.
    """
    global BACKUP
    global KEYS
    global CERTS
    global TMP
    if BACKUP == "":
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
            edit_config_(SERVICES[service], string, holder, section)
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
            backup_(file_path=file_path, name=name)
            test(*args, **kwargs)
            if restore:
                restore_file_(target=file_path, name=name, service=service)
                restart_service(service)

        return inner_wrapper

    return wrapper


def restore_file_(target, name, service=None):
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
    copy2(source, target)
    subp.run(["restorecon", "-v", target])
    restart_service(service)
    log.debug(f"File from {source} is restored to {target}")


def backup_(file_path, name=""):
    """
    Backup the file given in file_path to BACKUP directory.

    Args:
        sftp: SFTP connection to server for backup from this server
        file_path: path to fle
        name: file name in BACKUP directory
    """
    target = f"{BACKUP}/{name}"
    if isfile(file_path):
        copy2(file_path, target)
    elif isdir(file_path):
        copytree(file_path, target)
    log.debug(f"Source from {file_path} is copied to {target}")
    return target


def edit_config_(config: str, string: str, holder: str, section: bool):
    """
    Function for actual editing the config file.

    Args:
        config: path to config file
        string: string to be add
        holder: section or substring to update
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
        return code of systemctl restart
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


def generate_cert(username=None):
    """
    Function for generating the root CA certificate with keys

    Returns:
        tuple with path to the certificate and to the key files.
    """
    check_env()
    prefix = username if username == "root" else "User"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = randint(1, 1000)
    cert_path = f"{CERTS}/rootCA-{serial}.pem"
    key_path = f"{KEYS}/private-key-{serial}.pem"
    subject = issuer = ""
    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
    key_usage = None
    builder = x509.CertificateBuilder()

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))

    if username == "root":
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False,
            decipher_only=False)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"root-{serial}"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"root-{serial} Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"root-{serial} Test Ca"),
        ])
        if "ROOT_CRT" not in environ:
            with open(DOTNENV, "a") as f:
                f.write(f"ROOT_CRT={cert_path}")
    else:
        key_usage = x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False,
            decipher_only=False)
        try:
            root_cert_path = config("ROOT_CRT")
            root_crt = None
            if "pem" in root_cert_path:
                with open(root_cert_path, "rb") as f:
                    root_crt = x509.load_pem_x509_certificate(f.read())
            else:
                root_crt = x509.load_der_x509_certificate(root_cert_path)
            issuer = root_crt.issuer
            subject = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{prefix}-{serial}"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"{prefix}-{serial} Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{prefix}-{serial} Test Ca"),
            ])
        except UndefinedValueError:
            log.error("You are trying to generate user certificate, but .env "
                      "file do not have name for certificate issuer."
                      "Did you generate self-signed CA certificate?")

    subject_key = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    authority_key = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key)

    env_logger.debug("Type of subject is " + str(type(subject)))
    builder = builder \
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

    with open(cert_path, "wb") as f:
        f.write(builder.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path

def run_cmd(cmd: str = None, pin: bool = True,
            passwd: str = None, shell=None):
    """
    Run to create a child from current shell to run cmd. Try to assert
    expect pattern in the output of the cmd. If cmd require, provide
    login wth given PIN or password. Hitting reject pattern during cmd
    execution cause fail.

    Args:
        cmd: shell command to be executed
        pin: specify if passwd is a smart card PIN or a password for the
                user. Base on this, corresponding pattern would be matched
                in login output.
        passwd: smart card PIN or user password if login is needed
        shell: shell child where command need to be execute.
    Returns:
        stdout of executed command (cmd; see above)
    """
    try:
        if shell is None and cmd is not None:
            shell = pexpect.spawn("/bin/bash", ["-c", cmd + ' ; echo "RC:$?"'],
                                    encoding='utf-8')
        shell.logfile = sys.stdout

        if passwd is not None:
            pattern = "PIN for " if pin else "Password"
            out = shell.expect([pexpect.TIMEOUT, pattern], timeout=10)

            if out != 1:
                if out == 0:
                    log.error("Timed out on passsword / PIN waiting")
                expect = pattern

                raise PatternNotFound(f"Pattern '{pattern}' is not "
                                        f"found in the output.")
            shell.sendline(passwd)

    except PatternNotFound:
        log.error(f"Command: {cmd}")
        log.error(f"Output:\n{str(shell.before)}\n")
        raise
    return shell.read()

def check_output(output, expect: list = [], reject: list = [],
                    zero_rc: bool = True, check_rc: bool = False):
    """
    Check "output" for presence of expected and unexpected patterns.

    Check for presence of expected (required) and unexpected (disallowed)
    patterns in the text and raise exceptions if required pattern is missing
    or if any of disallowed patterns is present. Check also presence of
    pattern "RC:[0-9]+" that in current implementation of run_cmd represents
    exit value of executed command and raise an exception in case of
    non-zero value.

    Args:
        expect: list of patterns to be matched in the output
        reject: list of patterns that cause failure if matched in the output
        check_rc: indicates that presence of pattern "RC:0" would be checked
                    and an exception would be raised if the pattern is missing
        zero_rc: indicates that pattern "RC:[1-9]+" should be present
                    instead of "RC:0" and exception would not be raised
    """

    # TODO: add switch and functionality
    #  to check patterns in specified order
    for pattern in reject:
        if pattern in output:
            raise DisallowedPatternFound(f"Disallowed pattern '{pattern}' "
                                            f"was found in the output")

    for pattern in expect:
        if pattern not in output:
            log.error(f"Pattern: {pattern} not found in output")
            log.error(f"Output:\n{output}\n")
            raise PatternNotFound(f"Pattern '{expect}' is not "
                                    f"found in the output.")

    if check_rc:
        if "RC:0" not in output:
            msg = f"Non zero return code indicated"
            if zero_rc:
                raise NonZeroReturnCode(msg)
            else:
                log.warning(msg)

    return True
