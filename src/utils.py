import datetime
import difflib
import re
import subprocess as subp
from configparser import RawConfigParser
from os import listdir
from os.path import isdir, isfile, join, basename, split, exists
from random import randint
from shutil import copy2, copytree

import pexpect
import sys
from SCAutolib import env_logger, base_logger
from SCAutolib.src import env, read_config
from SCAutolib.src.exceptions import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from decouple import UndefinedValueError
from time import sleep

SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}


def show_file_diff(original, new):
    differ = difflib.Differ()
    with open(original, "r") as f:
        data_original = f.readlines()
    with open(new, "r") as f:
        data_new = f.readlines()
    diff = differ.compare(data_original, data_new)
    with open("/var/log/scautolib/edited_files.log", "a") as f:
        f.write("\n================\n")
        f.writelines(diff)
        f.write("================\n")
    return diff


def restore_file_(source, destination):
    """
    Restoring file from BACKUP directory to target. Target has to be a file.
    """
    copy2(source, destination)
    env.run(["restorecon", "-v", destination])
    base_logger.debug(f"File from {source} is restored to {destination}")


def backup_(file_path):
    """
    Backup the file given in file_path to BACKUP directory.

    Args:
        file_path: path to file to be saved
    Returns:
        Path to copied file/directory
    """
    backup_dir = read_config('backup', which='lib')
    file_name = basename(file_path)
    target = join(backup_dir, file_name + ".bak")
    if exists(target):
        return target

    if isfile(file_path):
        target = copy2(file_path, target)
    elif isdir(file_path):
        target = copytree(file_path, target)
    env.run(f"restorecon -v {target}")

    base_logger.debug(f"Source from {file_path} is copied to {target}")
    return target


def edit_config_(conf_file: str, section: str, key: str, value: str = "",
                 backup_name: str = ""):
    """
    Function for actual editing the config file.

    Args:
        conf_file: path to config file
        key: key to be updated
        value: value to be set for key
        section: section where a key is placed.
        backup_name: name of file where original file should be copied. If not
                     set, default name <original file name>.bak.<number of
                     copies would be used
    """
    cnf = RawConfigParser()
    cnf.optionxform = str

    with open(conf_file, "r") as file:
        cnf.read_file(file)

    if section not in cnf.sections():
        base_logger.error(
            f"Section {section} is not present in config file {conf_file}")
        raise UnknownOption(
            msg=f"Section {section} is not present in config file {conf_file}")

    cnf.set(section, key, value)

    with open(conf_file, "w") as file:
        cnf.write(file)
    backup_dir = read_config("backup", which="lib")
    file_name = basename(conf_file)

    if backup_name == "":
        count = len([i for i in listdir(backup_dir) if file_name in i])
        backup_name = file_name + f".bak.{count}"

    target = join(backup_dir, backup_name)
    copy2(conf_file, target)

    env_logger.debug(f"Current content of the file {conf_file} is copied "
                     f"to {target}")
    base_logger.debug(f"Value for key {key} in section {section} is set to "
                      f"{value} in file {conf_file}")


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
            result = env.run(
                ["systemctl", "restart", f"{service}"])
            sleep(5)
            env_logger.debug(f"Service {service} is restarted")
            return result.returncode
        except subp.CalledProcessError as e:
            env_logger.error(
                f"Command {' '.join(e.cmd)} is ended with non-zero return "
                f"code ({e.returncode})")
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
    tmp = read_config("tmp", which="lib")

    prefix = username if username == "root" else "User"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = randint(1, 1000)
    cert_path = f"{tmp}/rootCA{serial}.pem"
    key_path = f"{tmp}/private-key-{serial}.pem"
    subject = issuer = ""
    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
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
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, f"root-{serial} Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"root-{serial} Test Ca"),
        ])
    else:
        key_usage = x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False,
            decipher_only=False)
        try:
            root_cert_path = join(read_config("ca_dir", which="lib"), "rootCA.pem")
            with open(root_cert_path, "rb") as f:
                root_crt = x509.load_pem_x509_certificate(f.read())
            issuer = root_crt.issuer
            subject = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   f"{prefix}-{serial}"),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, f"{prefix}-{serial} Test"),
                x509.NameAttribute(NameOID.COMMON_NAME,
                                   f"{prefix}-{serial} Test Ca"),
            ])
        except UndefinedValueError:
            base_logger.error("You are trying to generate user certificate, "
                              "but .env file do not have name for certificate "
                              "issuer.Did you generate self-signed CA "
                              "certificate?")

    subject_key = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    authority_key = x509.AuthorityKeyIdentifier \
        .from_issuer_subject_key_identifier(subject_key)

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
        .sign(key, hashes.SHA256())  # noqa: E501

    with open(cert_path, "wb") as f:
        f.write(builder.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


def run_cmd(cmd: str = None, pin: bool = True, passwd: str = None, shell=None,
            return_val: str = "stdout"):
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
        return_val: return shell (shell) or stdout (stdout - default) or
                    both (all)
    Returns:
        stdout of executed command (cmd; see above)
    """
    try:
        if shell is None and cmd is not None:
            env_logger.warning("No shell given")
            cmd = ["-c", f'{cmd} ; echo "RC:$?"']
            shell = pexpect.spawn("/bin/bash", cmd, encoding='utf-8')
            env_logger.debug("Shell is spawned")
        shell.logfile = sys.stdout

        if passwd is not None:
            pattern = "PIN for " if pin else "Password"
            out = shell.expect([pexpect.TIMEOUT, pattern], timeout=10)

            if out != 1:
                if out == 0:
                    base_logger.error("Timed out on password / PIN waiting")

                raise PatternNotFound(f"Pattern '{pattern}' is not "
                                      f"found in the output.")
            shell.sendline(passwd)

    except PatternNotFound:
        base_logger.error(f"Command: {cmd}")
        base_logger.error(f"Output:\n{str(shell.before)}\n")
        raise

    if return_val == "stdout":
        return shell.read()
    elif return_val == "shell":
        return shell
    elif return_val == "all":
        return shell, shell.read()
    else:
        raise UnknownOption(option_val=return_val, option_name="return_val")


def check_output(output: str, expect=None, reject=None,
                 zero_rc: bool = False, check_rc: bool = False):
    """
    Check "output" for presence of expected and unexpected patterns.

    Check for presence of expected (required) and unexpected (disallowed)
    patterns in the text and raise exceptions if required pattern is missing
    or if any of disallowed patterns is present. Check also presence of
    pattern "RC:[0-9]+" that in current implementation of run_cmd represents
    exit value of executed command and raise an exception in case of
    non-zero value.

    Args:
        output: string where to look for expect/reject patterns. If check_rc
                and zero_rc are True, than string has to contain substring
                RC:<rc> where <rc> is a return value of the command. NOTE:
                substring with return value is automatically added by run_cmd
                function.
        expect: pattern or list of patterns to be matched in the output
        reject: pattern or list of  patterns that cause failure if matched in
                the output
        check_rc: if True, return code of the command will be checked. If False,
                  (default), return code is not checked.
        zero_rc: applicable only with check_rc = True. If zero_rc = True, return
                 code of the command has to ve 0, otherwise an exception
                 NonZeroReturnCode would be raise. If False (default), warning
                 would be added to logs instead of raising an exception.
    """

    # TODO: add switch and functionality
    #  to check patterns in specified order

    if reject is None:
        reject = []
    elif type(reject) == str:
        reject = [reject]

    if expect is None:
        expect = []
    elif type(expect) == str:
        expect = [expect]

    for pattern in reject:
        compiled = re.compile(pattern)
        if compiled.search(output) is not None:
            raise DisallowedPatternFound(f"Disallowed pattern '{pattern}' "
                                         f"was found in the output")

    for pattern in expect:
        compiled = re.compile(pattern)
        if compiled.search(output) is None:
            base_logger.error(f"Pattern: {pattern} not found in output")
            base_logger.error(f"Output:\n{output}\n")
            raise PatternNotFound(f"Pattern '{expect}' is not "
                                  f"found in the output.")

    if check_rc:
        if "RC:0" not in output:
            msg = "Non zero return code indicated"
            if zero_rc:
                raise NonZeroReturnCode(msg)
            else:
                base_logger.warning(msg)

    return True
