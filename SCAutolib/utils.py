"""
This module provides a set of additional helping functions that are used
across the library. These functions are based on library demands and are
not aimed to cover some general use-cases or specific corner cases.
"""
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

from SCAutolib import (run, logger, TEMPLATES_DIR, LIB_DUMP_USERS, LIB_DUMP_CAS,
                       LIB_DUMP_CARDS)
from SCAutolib.enums import OSVersion
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models.CA import LocalCA, BaseCA, CustomCA, IPAServerCA
from SCAutolib.models.card import Card
from SCAutolib.models.file import OpensslCnf, SSSDConf
from SCAutolib.models.user import User


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
    # CAC specification do not specify key size specifies key size
    # up to 2048 bits, so keys greater than 2048 bits is not supported
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

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
    elif "CentOS Stream release 8" in cnt:
        return OSVersion.CentOS_8
    elif "CentOS Stream release 9" in cnt:
        return OSVersion.CentOS_9
    else:
        raise SCAutolibException("OS is not detected.")


def _install_packages(packages):
    """
    Install given packages and log package version

    :param packages: list of packages to be installed
    """
    run(f"dnf install -y {' '.join(packages)}")
    for pkg in packages:
        pkg = run(["rpm", "-q", pkg]).stdout
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
    Store serialised object to the JSON file.
    """
    with obj.dump_file.open("w") as f:
        json.dump(obj.to_dict(), f)
    logger.debug(f"Object {type(obj)} is stored to the {obj.dump_file} file")


def load_user(username, **kwargs):
    """
    Load user with given username from JSON file.

    :param username: username of the user
    :type username: str

    :return: user object
    :rtype: BaseUser
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
    Load card with given name from JSON file. This function is intended to load
    card objects to tests during pytest configuration. If update_sssd param is
    True sssd.conf file will be updated based on card data

    :param card_name: name of the card to be loaded
    :type card_name: str
    :param update_sssd: indicates if sssd.conf matchrule should be updated based
        on card data
    :type update_sssd bool

    :return: card object
    :rtype: Card
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
        run(["systemctl", "restart", "sssd"])
    return card


def ipa_factory():
    """
    Create a new IPAServerCA object.

    .. note: Creating new IPA server with CA is not supported.

    :return: object of IPAServerCA
    :rtype: SCAutolib.models.CA.IPAServerCA
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
    Create CA object. If certain CA object was created in previous run of
    SCAutolib and it was serialized and saved in .json file, then such CA object
    would be initialized based on the file. If create param is True new CA
    object will be created regardless the presence of the .json file.

    :param path: path to the CA directory
    :type path: Path
    :param cnf: object representing openssl cnf file
    :type cnf: OpensslCnf object
    :param card_data: dictionary with various attributes of the card as PIN,
        cardholder, slot, etc.
    :type card_data: dict
    :param ca_name: name of CA that identifies CA file to be loaded if create
        parameter is set to False
    :type ca_name: str
    :param create: indicator to create new CA. If it's false existing CA files
        will be loaded
    :type create: bool
    :return: CA object
    :rtype: SCAutolib.models.CA object
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
