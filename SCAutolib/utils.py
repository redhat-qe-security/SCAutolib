"""
This module provides a collection of utility and helper functions utilized
across the SCAutolib library. These functions are
specifically designed to support various internal demands of the library,
including system checks, package management, key/certificate handling,
and data serialization. They are not intended as
general-purpose utilities but as specialized aids tailored to SCAutolib's
operations.
"""


import json
import distro
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Union
from pathlib import Path

from SCAutolib import run, logger, TEMPLATES_DIR, LIB_BACKUP


def _check_selinux():
    """
    Checks if a specific SELinux module, 'virtcacard' (for virtual smart cards),
    is currently installed and active on the system.
    If the module is not found, this function attempts to install it from
    a predefined template file (``virtcacard.cil``) and then restarts the
    ``pcscd`` service.

    :return: None
    """
    result = run("semodule -l", log=False)
    if "virtcacard" not in result.stdout:
        logger.debug(
            "SELinux module for virtual smart cards is not present in the "
            "system. Installing...")

        run(["semodule", "-i", f"{TEMPLATES_DIR}/virtcacard.cil"])

        run(["systemctl", "restart", "pcscd"])
        logger.debug("pcscd service is restarted")

    logger.debug("SELinux module for virtual smart cards is installed")


def _gen_private_key(key_path: Path, size: int = 2048):
    """
    Generates an RSA private key and saves it to the specified file path in PEM
    format without encryption.
    This function is used when a private key is needed for a user's smart card
    or certificate request and doesn't already exist.

    :param key_path: The ``pathlib.Path`` object specifying the full path
                     (including filename) where the generated private key
                     should be saved.
    :type key_path: pathlib.Path
    :param size: The size of the key in bits to be created.
    :type size: int
    :return: None
    """
    # CAC specification do not specify key size specifies key size
    # up to 2048 bits, so keys greater than 2048 bits is not supported
    key = rsa.generate_private_key(public_exponent=65537, key_size=size)

    with key_path.open("wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))


def _read_packages_json():
    packages_file = LIB_BACKUP.joinpath("packages.json")
    packages_json = {}

    if packages_file.exists():
        with packages_file.open("r") as f:
            packages_json = json.load(f)
    else:
        packages_json = {
            "installed": [],
            "removed": [],
        }

    return packages_file, packages_json


def _install_packages(packages: list[str]):
    """
    Installs a list of specified RPM packages on the system.
    After installation, it logs the installed version of each package for
    verification.

    :param packages: A list of strings, where each string is the name of a
                     package to be installed (e.g., ``["opensc", "sssd"]``).
    :type packages: list
    :return: None
    """
    packages_file, packages_json = _read_packages_json()

    run(f"dnf install -y {' '.join(packages)}")
    for pkg in packages:
        pkg = run(["rpm", "-q", pkg]).stdout
        logger.debug(f"Package {pkg} is installed")

    packages_json['installed'] += packages

    with packages_file.open("w") as f:
        json.dump(packages_json, f)


def _remove_packages(packages: list[str]):
    """
    Removes a list of specified RPM packages on the system.
    Before removal, it logs the installed version of each removed package.

    :param packages: A list of strings, where each string is the name of a
                     package to be installed (e.g., ``["opensc", "sssd"]``).
    :type packages: list
    :return: None
    """
    packages_file, packages_json = _read_packages_json()

    for pkg in packages:
        pkg = run(["rpm", "-q", pkg]).stdout
        logger.debug(f"Removing package {pkg}.")
    run(f"dnf remove -y {' '.join(packages)}")

    packages_json['removed'] += packages

    with packages_file.open("w") as f:
        json.dump(packages_json, f)


def _restore_packages():
    """
    Restore the system list of packages to the original state. Every package
    that was installed with _install_packages function will be removed and
    every package that was removed with _remove_packages will be restored.

    :return: None
    """
    packages_file, packages_json = _read_packages_json()

    if packages_json['removed']:
        run(f"dnf install -y {' '.join(packages_json['removed'])}")
    if packages_json['installed']:
        run(f"dnf remove -y {' '.join(packages_json['installed'])}")
    logger.debug("Restored original system packages.")

    if packages_file.exists():
        packages_file.unlink()


def _check_packages(packages: list[str]):
    """
    Identifies and returns a list of packages that are required for SCAutolib
    but are not currently installed on the system.
    It uses ``rpm -q`` to query each package's installation status.

    :param packages: A list of strings, where each string is the name of a
                     package to check for.
    :type packages: list
    :return: A list of strings, containing the names of packages that were
             found to be missing on the system.
    :rtype: list
    """
    missing = []
    for pkg in packages:
        # Return code 1 means the package is not installed
        out = run(["rpm", "-q", pkg], return_code=[0, 1])
        if out.returncode == 1:
            logger.warning(f"Package {pkg} is required for the testing, "
                           f"but is not present in the system")
            missing.append(pkg)
        else:
            logger.debug(f"Package {out.stdout.strip()} is present")
    return missing


def dump_to_json(obj: any):
    """
    Serializes a given object into a JSON file, using the object's
    ``to_dict()`` method for serialization and its ``dump_file`` attribute to
    determine the output path. This is used to persist
    the state of SCAutolib's internal objects (like users, CAs, and cards)
    across different runs.

    :param obj: The object to be serialized. It must have a ``to_dict()``
                method and a ``dump_file`` attribute.
    :type obj: object
    :return: None
    """
    with obj.dump_file.open("w") as f:
        json.dump(obj.to_dict(), f)
    logger.debug(f"Object {type(obj)} is stored to the {obj.dump_file} file")


def isDistro(OSes: Union[str, list], version: str = None) -> bool:
    """
    Identifies if the current operating system matches a specified distribution
    and, optionally, its version. This function leverages the ``distro`` library
    to determine the system's ID, name, and version details.

    :param OSes: The ID or name of the operating system(s) to check against.
                 Can be a single string (e.g., "fedora", "rhel") or a list of
                 strings. Case-insensitive comparison is performed.
    :type OSes: Union[str, list]
    :param version: An optional string specifying the version to check. It can
                    include comparison operators
                    (``<``, ``<=``, ``==``, ``>``, ``>=``).
                    If no operator is specified, ``==`` is assumed.
                    Examples: "8", ">=9", "<39".
    :type version: str, optional
    :return: ``True`` if the current operating system matches the specified
             distribution(s) and version criteria; ``False`` otherwise.
    :rtype: bool
    """

    cur_id = distro.id().lower()
    cur_name = distro.name().lower()

    if isinstance(OSes, str):
        results = (OSes in cur_id) or (OSes in cur_name)
    else:
        results = False
        for item in OSes:
            if not isinstance(item, str):
                continue
            item = item.lower()
            results = results or (item in cur_id) or (item in cur_name)

    if results is False:
        return False

    if version:
        cur_major = int(distro.major_version())
        cur_minor = int(distro.minor_version()) if distro.minor_version() else 0

        if version[0] in ('<', '=', '>'):
            if version[1] == '=':
                op = version[:2]
                version = version[2:]
            else:
                op = version[0] if version[0] != '=' else '=='
                version = version[1:]
        else:
            op = '=='

        parts = version.split('.')
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else None

        if major == cur_major and minor:
            return eval("{0} {1} {2}".format(cur_minor, op, minor))
        else:
            return eval("{0} {1} {2}".format(cur_major, op, major))

    return True
