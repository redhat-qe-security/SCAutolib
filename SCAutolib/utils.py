from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

from enum import Enum

from SCAutolib import run, logger, TEMPLATES_DIR


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
    else:
        return OSVersion.Fedora


def _install_packages(packages):
    """
    Install given packages and log package version

    :param packages: list of packages to be installed
    """
    for pkg in packages:
        logger.warning(f"Package {pkg} is not installed on the "
                       f"system. Installing...")
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
                           f"but doesn't present in the system")
            missing.append(pkg)
        else:
            logger.debug(f"Package {out.stdout.strip()} is present")
    return missing
