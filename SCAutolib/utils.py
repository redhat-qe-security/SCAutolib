"""
Define utility and helper functions for the SCAutolib library.

These functions support internal demands including system checks, package
management, key/certificate handling, and data serialization. They are
tailored specifically for SCAutolib's operations.
"""


import json
import distro
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Union, Any
from pathlib import Path
from configparser import ConfigParser
from io import TextIOWrapper

from SCAutolib import run, logger, TEMPLATES_DIR, LIB_BACKUP


class MultiEntryDict(dict):
    """
    A dictionary subclass that merges list values for duplicate keys.

    This dictionary is customized for use with `ConfigParser` where multi-line
    or duplicate options may be processed as lists. Instead of
    overwriting an existing list value, it appends new list items to the
    existing ones.
    """

    def __setitem__(self, key: str, value: Any):
        """
        Set the value for a given key, merging lists if the key already exists.

        If both the existing value and the incoming value are lists, they are
        concatenated. Otherwise, the standard dictionary assignment is used.

        :param key: The key to set.
        :type key: str
        :param value: The value to associate with the key.
        :type value: Any
        :return: None
        :rtype: None
        """
        # ConfigParser temporarily stores values as a list of lines during
        # parsing. If the key already exists, we merge the lists instead of
        # overwriting.
        areLists = isinstance(value, list) and isinstance(self[key], list)
        if (
            key in self and areLists
        ):
            super().__setitem__(key, self[key] + value)
        else:
            super().__setitem__(key, value)


class CustomConfigParser(ConfigParser):
    """
    A custom ConfigParser that supports duplicate keys and continuations.

    By utilizing `MultiEntryDict` as its internal dictionary type and disabling
    strict mode, this parser handles configuration files containing multiple
    identical keys within a single section without overwriting them.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the CustomConfigParser with non-strict multi-entry support.

        :param args: Positional arguments passed to the parent `ConfigParser`.
        :type args: list
        :param kwargs: Keyword arguments passed to the parent `ConfigParser`.
        :type kwargs: dict
        :return: None
        :rtype: None
        """
        super().__init__(
            *args, **kwargs, dict_type=MultiEntryDict, strict=False,
        )

    def _write_section(
        self, fp: TextIOWrapper, section_name: str, section_items: list[str],
        delimiter: str
    ):
        r"""
        Write a single section and its items to a file-like object.

        This overrides the default section writing behavior to match formats
        like systemd configuration files. It duplicates key names for
        multi-line entries unless a line explicitly ends with a backslash
        (`\\`), which triggers a standard indented continuation line.

        :param fp: A file-like object open for writing.
        :type fp: TextIOWrapper
        :param section_name: The name of the section being written.
        :type section_name: str
        :param section_items: An iterable of (key, value) pairs to write.
        :type section_items: list[str]
        :param delimiter: The delimiter string separating keys and values.
        :type delimiter: str
        :return: None
        :rtype: None
        """
        fp.write("[{}]\n".format(section_name))
        for key, value in section_items:
            value = self._interpolation.before_write(
                self, section_name, key, value)
            if value is not None:
                lines = str(value).split('\n')
                is_continuation = False

                for line in lines:
                    if is_continuation:
                        # Keep it as an indented continuation line if the
                        # previous line ended in \
                        fp.write("\t{}\n".format(line.strip()))
                    else:
                        # Otherwise, repeat the key name for duplicate options
                        fp.write("{}{}{}\n".format(key, delimiter, line))

                    # Systemd uses a trailing backslash to denote a split
                    # single line
                    if line.strip().endswith('\\'):
                        is_continuation = True
                    else:
                        is_continuation = False
            elif not self._allow_no_value:
                fp.write("{}{}\n".format(key, delimiter))
            else:
                fp.write("{}\n".format(key))
        fp.write("\n")


def _check_selinux():
    """
    Check if the 'virtcacard' SELinux module is active.

    If the module is not found, it attempts to install it from the
    template file and restarts the ``pcscd`` service.

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
    Generate an unencrypted RSA private key in PEM format.

    The key is saved to the specified path. Note that sizes greater than
    2048 bits are typically not supported by CAC specifications.

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


def _read_packages_json() -> tuple[Path, dict[str, list]]:
    """
    Read the package tracking JSON file from the backup directory.

    If the file does not exist, it returns a default structure.

    :return: A tuple containing the file path and the package data dictionary.
    :rtype: tuple[Path, dict]
    """
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
    Install a list of RPM packages and log their versions.

    The installation is tracked in the package backup JSON file.

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
    Remove a list of RPM packages from the system.

    The removal is tracked in the package backup JSON file.

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
    Restore system packages to their original state.

    Removes all packages installed via ``_install_packages`` and
    reinstalls those removed via ``_remove_packages``.

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


def _check_packages(packages: list[str]) -> list[str]:
    """
    Identify missing required packages on the system.

    Queries the RPM database to check the installation status of each
    package in the provided list.

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
    Serialize an object into a JSON file for persistence.

    The object must implement a ``to_dict()`` method and have a
    ``dump_file`` attribute.

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
    Check if the current OS matches a specified distribution and version.

    Leverages the ``distro`` library to verify system IDs, names, and
    versions using optional comparison operators.

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
