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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

from SCAutolib import (run, logger, TEMPLATES_DIR, LIB_DUMP_USERS, LIB_DUMP_CAS,
                       LIB_DUMP_CARDS)
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models.CA import LocalCA, BaseCA, CustomCA, IPAServerCA
from SCAutolib.models.card import Card
from SCAutolib.models.file import OpensslCnf, SSSDConf
from SCAutolib.models.user import User


def _check_selinux():
    """
    Checks if a specific SELinux module, 'virtcacard' (for virtual smart cards),
    is currently installed and active on the system.
    If the module is not found, this function attempts to install it from
    a predefined template file (``virtcacard.cil``) and then restarts the
    ``pcscd`` service.

    :return: None
    """
    result = run("semodule -l", print_=False)
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


def _install_packages(packages):
    """
    Installs a list of specified RPM packages on the system.
    After installation, it logs the installed version of each package for
    verification.

    :param packages: A list of strings, where each string is the name of a
                     package to be installed (e.g., ``["opensc", "sssd"]``).
    :type packages: list
    :return: None
    """
    run(f"dnf install -y {' '.join(packages)}")
    for pkg in packages:
        pkg = run(["rpm", "-q", pkg]).stdout
        logger.debug(f"Package {pkg} is installed")


def _check_packages(packages):
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


def dump_to_json(obj):
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


def load_user(username, **kwargs):
    """
    Loads a ``User`` object from a JSON dump file corresponding to the given
    username. The file is expected to be located in ``LIB_DUMP_USERS``
    directory.

    :param username: The username of the user to load.
    :type username: str
    :param kwargs: Additional keyword arguments that might be required by the
                   ``User.load`` static method, particularly for ``IPAUser``
                   objects (e.g., ``ipa_server`` object).
    :type kwargs: dict
    :return: The loaded ``User`` object (either ``User`` or ``IPAUser``
             instance).
    :rtype: SCAutolib.models.user.User
    :raises SCAutolibException: If the user's JSON dump file does not exist.
    """
    user_file = LIB_DUMP_USERS.joinpath(f"{username}.json")
    logger.debug(f"Loading user {username} from {user_file}")
    user = None
    if user_file.exists():
        user = User.load(user_file, **kwargs)
    else:
        raise SCAutolibException(f"{user_file} does not exist")
    return user


def load_token(card_name: str = None, update_sssd: bool = False):
    """
    Loads a ``Card`` object from a JSON dump file based on the provided card
    name. This function is primarily intended for use
    in pytest configurations to set up card objects for tests.
    Optionally, it can update the SSSD configuration file (``sssd.conf``)
    with a ``shadowutils`` rule for the user of the loaded card.

    :param card_name: The name of the card object to load.
    :type card_name: str, optional
    :param update_sssd: If ``True``, the SSSD configuration file will be
                        updated with a ``shadowutils`` rule for the user of the
                        loaded card.
    :return: The loaded ``Card`` object
    :rtype: SCAutolib.models.card.Card
    """
    card_file = LIB_DUMP_CARDS.joinpath(f"{card_name}.json")
    logger.debug(f"Loading card {card_name} from {card_file}")
    card = None
    if card_file.exists():
        card = Card.load(card_file)
    if update_sssd:
        sssd_conf = SSSDConf()
        sssd_conf.set(section=f"certmap/shadowutils/{card.cardholder}",
                      key="matchrule",
                      value=f"<SUBJECT>.*CN={card.CN}.*")
        sssd_conf.save()
        run(["sss_cache", "-E"])
        run(["systemctl", "restart", "sssd"])
    return card


def ipa_factory():
    """
    Creates and returns an ``IPAServerCA`` object. This function
    loads the IPA server CA configuration from its JSON dump file.
    It specifically asserts that the loaded CA is an instance of
    ``IPAServerCA``.

    .. note: Creating new IPA server with CA is not supported.

    :return: An initialized ``IPAServerCA`` object.
    :rtype: SCAutolib.models.CA.IPAServerCA
    :raises SCAutolibException: If the IPA server CA dump file is not found
                                or if the loaded object is not a valid
                                ``IPAServerCA`` instance.
    """
    json_file = LIB_DUMP_CAS.joinpath("ipa-server.json")
    if not json_file.exists():
        msg = "Dump file for ipa server CA is not present."
        logger.error(msg)
        logger.error("The reason for this is most likely that the system was "
                     "not configured for IPA client via SCAutolib")
        raise SCAutolibException(msg)
    ca = BaseCA.load(json_file)
    if not isinstance(ca, IPAServerCA):
        msg = "Values in dump file are not valid for IPA server, so the " \
              "object can't be created"
        logger.error(msg)
        raise SCAutolibException(msg)
    return ca


def ca_factory(path: Path = None, cnf: OpensslCnf = None,
               card_data: dict = None, ca_name: str = None,
               create: bool = False):
    """
    A factory function to create or load Certificate Authority (CA) objects
    based on the provided parameters. It can initialize
    a new CA instance or load an existing one from a JSON dump file.

    :param path: The ``pathlib.Path`` object to the CA's root directory. This is
                 used when creating a new ``LocalCA`` instance.
    :type path: pathlib.Path, optional
    :param cnf: An ``OpensslCnf`` object representing the OpenSSL configuration
                file for the CA. Used when creating a new ``LocalCA``.
    :type cnf: SCAutolib.models.file.OpensslCnf, optional
    :param card_data: A dictionary containing various attributes of the card
                      (e.g., PIN, cardholder, slot). This data is used when
                      creating a new ``CustomCA`` for physical cards.
    :type card_data: dict, optional
    :param ca_name: The name of the CA to load. This parameter is used when
                    ``create`` is ``False`` to identify the specific CA JSON dump
                    file.
    :type ca_name: str, optional
    :param create: If ``True``, a new CA object will be created
                   (either ``LocalCA`` or ``CustomCA``). If ``False``,
                   an existing CA object will be loaded from a dump file.
    :type create: bool
    :return: An initialized CA object (either ``LocalCA``, ``CustomCA``, or
             ``IPAServerCA`` instance).
    :rtype: SCAutolib.models.CA.BaseCA
    """
    if not create:
        ca = BaseCA.load(LIB_DUMP_CAS.joinpath(f"{ca_name}.json"))
        return ca

    if not path:            # create CA for physical card
        ca = CustomCA(card_data)
        return ca
    else:                   # create new CA object for virtual card
        ca = LocalCA(root_dir=path, cnf=cnf)
        return ca
