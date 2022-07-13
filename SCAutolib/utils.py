"""
This module provides different additional helping functions that are used
across the library. These functions are made based on library demands and are
not attended to cover some general use-cases or specific corner cases.
"""
import json
import pexpect
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from enum import Enum
from pathlib import Path
import sys

from SCAutolib import run, logger, TEMPLATES_DIR
from SCAutolib.exceptions import (SCAutolibException, PatternNotFound,
                                  UnknownOption, DisallowedPatternFound,
                                  NonZeroReturnCode)


class OSVersion(Enum):
    """
    Enumeration for Linux versions. Used for more convenient checks.
    """
    Fedora = 1
    RHEL_9 = 2
    RHEL_8 = 3


def _check_selinux():
    """
    Checks if specific SELinux module for virtual smart card is installed.
    This is implemented be checking the hardcoded name for the module
    (virtcacard) to be present in the list of SELinux modules. If this name is
    not present in the list, then virtcacard.cil file would be created in conf
    or subdirectory in the CA directory specified by the configuration file.
    """
    result = run("semodule -l", print_=False)
    if "virtcacard" not in result.stdout:
        logger.debug(
            "SELinux module for virtual smart cards is not present in the "
            "system. Installing...")

        run(["semodule", "-i", f"{TEMPLATES_DIR}/virtcacard.cil"])

        run(["systemctl", "restart", "pcscd"])
        logger.debug("pcscd service is restarted")

    logger.debug(
        "SELinux module for virtual smart cards is installed")


def _gen_private_key(key_path: Path):
    """
    Generate RSA private key to specified location.

    :param key_path: path to output certificate
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    with key_path.open("wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))


def _get_os_version():
    """
    Find Linux version. Available version: RHEL 8, RHEL 9, Fedora.
    :return: Enum with OS version
    """
    with open('/etc/redhat-release', "r") as f:
        cnt = f.read()

    if "Red Hat Enterprise Linux release 9" in cnt:
        return OSVersion.RHEL_9
    elif "Red Hat Enterprise Linux release 8" in cnt:
        return OSVersion.RHEL_8
    elif "Fedora" in cnt:
        return OSVersion.Fedora
    else:
        raise SCAutolibException("OS is not detected.")


def _install_packages(packages):
    """
    Install given packages and log package version

    :param packages: list of packages to be installed
    """
    for pkg in packages:
        run(f"dnf install {pkg} -y")
        pkg = run(["rpm", "-qa", pkg]).stdout
        logger.debug(f"Package {pkg} is installed")


def _check_packages(packages):
    """
    Find missing packages

    :param packages: list of required packages
    :type packages: list
    :return: list of missing packages
    """
    missing = []
    for pkg in packages:
        out = run(["rpm", "-qa", pkg])
        if pkg not in out.stdout:
            logger.warning(f"Package {pkg} is required for the testing, "
                           f"but is not present in the system")
            missing.append(pkg)
        else:
            logger.debug(f"Package {out.stdout.strip()} is present")
    return missing


def dump_to_json(obj):
    """
    Store serialised object to the JSON file.
    """
    with obj.dump_file.open("w") as f:
        json.dump(obj.__dict__, f)
    logger.debug(f"Object {type(obj)} is stored to the {obj.dump_file} file")


def restart_service(service_name):
    logger.debug(f"Restarting {service_name} service")
    run(["systemctl", "restart", service_name])
    logger.debug(f"Service {service_name} successfully restarted")


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
            cmd = ["-c", f'{cmd} ; echo "RC:$?"']
            shell = pexpect.spawn("/bin/bash", cmd, encoding='utf-8')
        shell.logfile = sys.stdout

        if passwd is not None:
            pattern = "PIN for " if pin else "Password"
            out = shell.expect([pexpect.TIMEOUT, pattern], timeout=10)

            if out != 1:
                if out == 0:
                    logger.error("Timed out on password / PIN waiting")
                raise PatternNotFound(f"Pattern '{pattern}' is not "
                                      f"found in the output.")
            shell.sendline(passwd)

    except PatternNotFound:
        logger.error(f"Command: {cmd}")
        logger.error(f"Output:\n{str(shell.before)}\n")
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
            logger.error(f"Pattern: {pattern} not found in output")
            logger.error(f"Output:\n{output}\n")
            raise PatternNotFound(f"Pattern '{expect}' is not "
                                  f"found in the output.")

    if check_rc:
        if "RC:0" not in output:
            msg = "Non zero return code indicated"
            if zero_rc:
                raise NonZeroReturnCode(msg)
            else:
                logger.warning(msg)

    return True
