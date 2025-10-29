"""
This module defines the ``Controller`` class, which serves as the central
orchestrator for SCAutolib's operations.

It bridges the gap between the CLI (View) or automated test scripts and the
underlying Model components (like CAs, users, and cards).
The ``Controller`` is responsible for high-level logic, including system
preparation, CA configuration, user and smart card setup, and overall
cleanup. It manages the flow of actions,
validates configurations, and handles the persistence of critical object
states.
"""


import json
import os
from pathlib import Path
from schema import Schema, Use
from shutil import rmtree
from typing import Union

from SCAutolib import schema_cas, schema_user, schema_card
from SCAutolib import (logger, run, LIB_DIR, LIB_BACKUP, LIB_DUMP,
                       LIB_DUMP_USERS, LIB_DUMP_CAS, LIB_DUMP_CARDS,
                       LIB_DUMP_CONFS, TEMPLATES_DIR)
from SCAutolib.models import CA, file, user, card, authselect as auth
from SCAutolib.models.file import File, OpensslCnf
from SCAutolib.models.CA import BaseCA, LocalCA, IPAServerCA
from SCAutolib.enums import (CardType, UserType)
from SCAutolib.utils import (_check_selinux, _gen_private_key,
                             _install_packages, _restore_packages,
                             _check_packages, dump_to_json, isDistro)
from SCAutolib.exceptions import *


class Controller:
    """
    The ``Controller`` class acts as the central logic unit within SCAutolib,
    orchestrating complex workflows involving system setup, CA management,
    user creation, and smart card enrollment. It initializes
    and manages various model objects (e.g., ``Authselect``, ``SSSDConf``,
    ``CA``'s, ``User``'s, ``Card``'s) and executes their methods in a
    coordinated manner to achieve desired system states for smart card testing.
    """
    authselect: auth.Authselect = auth.Authselect()
    sssd_conf: file.SSSDConf = file.SSSDConf()
    lib_conf: dict = None
    _lib_conf_path: Path = None
    local_ca: CA.LocalCA = None
    ipa_ca: CA.IPAServerCA = None
    custom_cas: list[CA.CustomCA] = []
    users: [user.User] = None
    dconf_file = File(filepath='/etc/dconf/db/local.d/gnome_disable_welcome',
                      template=Path(TEMPLATES_DIR, 'gnome_disable_welcome'))

    virtual_cards_packages = ["virt_cacard", "vpcd", "softhsm"]

    @property
    def conf_path(self):
        """
        Returns the absolute path to the configuration file loaded by the
        Controller.

        :return: A ``pathlib.Path`` object representing the absolute path of
                 the loaded configuration file.
        :rtype: pathlib.Path
        """
        return self._lib_conf_path

    def __init__(self, config: Union[Path, str] = None, params: dict = None):
        """
        Initializes the Controller, parsing and validating the input
        configuration file. If values are missing
        from the configuration, it checks if they are provided via CLI
        parameters. It also sets up necessary
        dump and backup directories and initializes related model objects (CAs)
        from previous runs if their dump files exist.

        :param config: Path to the JSON configuration file containing metadata
                       for testing setup.
        :type config: pathlib.Path or str, optional
        :param params: A dictionary of parameters typically originating from
                       CLI arguments, used to supplement or override values
                       from the configuration file.
        :type params: dict, optional
        :return: None
        """

        # Check params

        # Parse config file
        self.lib_conf = None
        if config:
            self._lib_conf_path = config.absolute() if isinstance(config, Path) \
                else Path(config).absolute()

            with self._lib_conf_path.open("r") as f:
                tmp_conf = json.load(f)
                if tmp_conf is None:
                    raise SCAutolibWrongConfig(
                        "Data are not loaded correctly.")
            self.lib_conf = self._validate_configuration(tmp_conf, params)

        self.users = []
        for d in (LIB_DIR, LIB_BACKUP, LIB_DUMP, LIB_DUMP_USERS, LIB_DUMP_CAS,
                  LIB_DUMP_CARDS, LIB_DUMP_CONFS):
            d.mkdir(exist_ok=True)

        for ca_file in LIB_DUMP_CAS.iterdir():
            ca = BaseCA.load(ca_file)

            if type(ca) is LocalCA:
                self.local_ca = ca
            elif type(ca) is IPAServerCA:
                self.ipa_ca = ca
            else:
                self.custom_cas.append(ca)

    def prepare(self, force: bool, gdm: bool, install_missing: bool,
                graphical: bool):
        """
        Prepares the entire system for smart card testing based on the loaded
        configuration and provided CLI options. This method
        orchestrates the complex configuration of the system under test,
        including setting up Certificate Authorities (CAs), creating users,
        and configuring smart cards.

        :param force: If ``True``, existing objects, files, users, or services
                      will be erased or overwritten if they already exist. Its
                      exact meaning can vary slightly for different internal
                      methods.
        :type force: bool
        :param install_missing: If ``True``, all detected missing prerequisite
                                packages will be automatically installed.
        :type install_missing: bool
        :param gdm: If ``True``, the GDM (GNOME Display Manager) package will
                    be installed as part of system preparation.
        :type gdm: bool
        :param graphical: If ``True``, dependencies specifically required for
                          GUI testing will be installed.
        :type graphical: bool
        :return: None
        :raises SCAutolibWrongConfig: If a required CA section is missing in
                                      the configuration.
        """

        self.setup_system(install_missing, gdm, graphical)

        # Prepare CAs: Virtual cards are populated by certificates that are: a)
        # created locally and signed by local CA configured on the system under
        # test, or b) created and signed using FreeIPA.
        try:
            self.setup_local_ca(force=force)
        except SCAutolibWrongConfig as e:
            logger.info(e)
        try:
            self.setup_ipa_client(force=force)
        except SCAutolibWrongConfig as e:
            logger.info(e)
        try:
            self.setup_custom_ca(force=force)
        except SCAutolibWrongConfig as e:
            logger.info(e)

        for usr in self.lib_conf["users"]:
            self.setup_user(usr, force=force)

        # Create cards defined in config. For physical cards only objects will
        # be created while for virtual cards tokens will be created and enrolled
        for token in self.lib_conf["cards"]:
            # prepare CA objects for physical cards
            if token["card_type"] == CardType.physical:
                self.setup_card(token)
            elif token["card_type"] == CardType.virtual:
                c = self.setup_card(token)
                self.enroll_card(c)

    def has_card(self, card_type: CardType):
        """
        A helper function that checks if a card of a card_type is defined in
        the config.

        :param card_type: The type of the card to check if it is defined in
                          the config.
        :type card_type: CardType
        :return: ``True`` if a card of card type is defined in the config;
            ``False`` otherwise.
        :rtype: bool
        """
        return any(c["card_type"] == card_type for c in self.lib_conf["cards"])

    def has_user(self, user_type: UserType):
        """
        A helper function that checks if a user of a user_type is defined in
        the config.

        :param user_type: The type of the card to check if it is defined in
                          the config.
        :type user_type: UserType
        :return: ``True`` if a user of user_type is defined in the config;
            ``False`` otherwise.
        :rtype: bool
        """
        return any(u["user_type"] == user_type for u in self.lib_conf["users"])

    def setup_system(self, install_missing: bool, gdm: bool, graphical: bool):
        """
        Performs general system setup, including the installation of necessary
        packages, SSSD configuration, and specific configurations for virtual
        smart cards based on the requirements defined in the configuration
        file.

        :param install_missing: If ``True``, all detected missing prerequisite
                                packages will be automatically installed.
        :type install_missing: bool
        :param gdm: If ``True``, the GDM (GNOME Display Manager) package will
                    be installed as part of system preparation.
        :type gdm: bool
        :param graphical: If ``True``, dependencies specifically required for
                          GUI testing will be installed.
        :type graphical: bool
        :return: None
        :raises SCAutolibException: If required packages are missing and
                                    ``install_missing`` is ``False``.
        """

        for d in (LIB_DIR, LIB_BACKUP, LIB_DUMP, LIB_DUMP_USERS, LIB_DUMP_CAS,
                  LIB_DUMP_CARDS):
            d.mkdir(exist_ok=True)

        packages = ["opensc", "httpd", "sssd", "sssd-tools", "gnutls-utils",
                    "openssl", "nss-tools"]

        # Prepare for virtual cards
        if self.has_card(CardType.virtual):
            packages += ["pcsc-lite", "pcsc-lite-ccid"]
            packages += self.virtual_cards_packages
            run("dnf -y copr --hub fedora enable jjelen/vsmartcard")

        # Prepare for physical cards
        if self.has_card(CardType.physical):
            # TODO: Change when a new release of removinator is in PyPI
            # From more info, see
            # https://github.com/nkinder/smart-card-removinator/issues/11
            run([
                'pip', 'install',
                'git+https://github.com/nkinder/smart-card-removinator.git'
                '#egg=removinator&subdirectory=client'
            ])

        # Add IPA packages if needed
        if self.has_user(UserType.ipa):
            packages += self._general_steps_for_ipa()

        # Check for installed packages
        missing = _check_packages(packages)
        if install_missing and missing:
            _install_packages(missing)
        elif missing:
            msg = "Can't continue. Some packages are missing: " \
                  f"{', '.join(missing)}"
            logger.critical(msg)
            raise SCAutolibException(msg)

        if graphical:
            self.setup_graphical(install_missing, gdm)

        if not isDistro('fedora'):
            run(['dnf', 'groupinstall', "Smart Card Support", '-y',
                 '--allowerasing'])
            logger.debug("Smart Card Support group in installed.")
        else:
            # Fedora requires rsyslog as well
            run(['dnf', 'install', 'opensc', 'pcsc-lite-ccid', 'rsyslog', '-y'])
            run(['systemctl', 'start', 'rsyslog'])

        self.sssd_conf.create()
        self.sssd_conf.save()

        if self.has_card(CardType.virtual):
            self._general_steps_for_virtual_sc()

        base_user = user.User("base-user", "redhat")
        base_user.add_user()
        dump_to_json(base_user)
        dump_to_json(user.User(username="root",
                               password=self.lib_conf["root_passwd"]))

    def setup_graphical(self, install_missing: bool, gdm: bool):
        """
        Configures the system specifically for GUI testing.
        This involves installing necessary graphical user interface (GUI)
        packages and ensuring the environment is ready for GUI automation.

        :param install_missing: If ``True``, all detected missing prerequisite
                                packages will be automatically installed.
        :type install_missing: bool
        :param gdm: If ``True``, the GDM (GNOME Display Manager) package will
                    be installed as part of system preparation.
        :type gdm: bool
        :return: None
        :raises SCAutolibGUIException: If required packages are missing and
                                      ``install_missing`` is ``False``.
        """

        packages = ["gcc", "tesseract", "ffmpeg-free"]

        if gdm:
            packages.append("gdm")

        missing = _check_packages(packages)
        if install_missing and missing:
            _install_packages(missing)
        elif missing:
            msg = "Can't continue with graphical. Some packages are missing: " \
                  f"{', '.join(missing)}"
            logger.critical(msg)
            raise SCAutolibGUIException(msg)

        if not isDistro('fedora'):
            run(['dnf', 'groupinstall', 'Server with GUI', '-y',
                '--allowerasing'])
            run(['pip', 'install', 'python-uinput'])
        else:
            # Fedora doesn't have server with GUI group so installed gdm
            # manually and also python3-uinput should be installed from RPM
            run(['dnf', 'install', 'gdm', 'python3-uinput', '-y'])
        # disable subscription message
        run(['systemctl', '--global', 'mask',
            'org.gnome.SettingsDaemon.Subscription.target'])
        # disable welcome message
        if not self.dconf_file.exists():
            self.dconf_file.create()
            self.dconf_file.save()
            run('dconf update')

    def setup_local_ca(self, force: bool = False):
        """
        Configures a local Certificate Authority (CA) based on the settings
        from the configuration file. It ensures the
        necessary directory and file structures are created and the CA's
        self-signed root certificate is generated.
        It also updates the system's ``sssd_auth_ca_db.pem`` with the CA's
        certificate.

        :param force: If ``True``, any existing local CA in the
                      specified directory will be removed before creating the
                      new one.
        :type force: bool
        :return: None
        :raises SCAutolibWrongConfig: If the 'local_ca' section is not found
                                      in the configuration file.
        """

        if "local_ca" not in self.lib_conf["ca"]:
            msg = "Section for local CA is not found in the configuration file"
            raise SCAutolibWrongConfig(msg)

        ca_dir: Path = self.lib_conf["ca"]["local_ca"]["dir"]
        ca_dir.mkdir(exist_ok=True, parents=True)

        cnf = OpensslCnf(ca_dir.joinpath("ca.cnf"), "CA", str(ca_dir))
        self.local_ca = BaseCA.factory(path=ca_dir, cnf=cnf, create=True)
        if force:
            logger.warning(f"Removing previous local CA from {ca_dir}")
            self.local_ca.cleanup()
        cnf.create()
        cnf.save()
        self.local_ca.setup()

        logger.info(f"Local CA is configured in {ca_dir}")

        dump_to_json(self.local_ca)

    def setup_custom_ca(self, force: bool):
        """
        Sets up a custom Certificate Authority (CA) based on provided card
        data. This is typically used for physical cards
        where root CA certificates might be provided externally and cannot be
        changed (like precreated physical cards).
        It creates the CA object, performs its setup, and then dumps its state
        to a JSON file.

        :param card_data: A dictionary containing details about the card, which
                          includes information about its associated CA.
        :type card_data: dict
        :return: None
        :raises SCAutolibFileNotExists: If the CA certificate file is not found
                                        after setup.
        """

        if "custom" not in self.lib_conf["ca"]:
            raise SCAutolibWrongConfig("Section for custom CAs is not found "
                                       "in the configuration file")

        for ca_data in self.lib_conf["ca"]["custom"]:
            ca_path = LIB_DUMP_CAS.joinpath(f"{ca_data['name']}.json")
            if ca_path.exists():
                if force:
                    ca_path.unlink()
                else:
                    continue

            ca = BaseCA.factory(create=True, ca_name=ca_data["name"],
                                ca_cert=ca_data["ca_cert"])
            ca.setup()
            if not ca._ca_cert.is_file():
                raise SCAutolibFileNotExists(f"File not found: {ca._ca_cert}")
            self.custom_cas.append(ca)
            dump_to_json(ca)

    def setup_ipa_client(self, force: bool = False):
        """
        Configures an IPA (Identity Management for Linux) client on the current
        host to communicate with a given IPA server. The IPA
        server is expected to be already operational. If an IPA
        client is already installed, it can be optionally removed before
        reconfiguration.

        :param force: If ``True`` and an IPA Client is already configured, the
                      existing installation will be uninstalled before setting
                      up the new client.
        :type force: bool
        :return: None
        :raises SCAutolibWrongConfig: If the 'ipa' section is not found in the
                                      configuration file.
        """

        if "ipa" not in self.lib_conf["ca"]:
            msg = "Section for IPA is not found in the configuration file"
            raise SCAutolibWrongConfig(msg)
        self.ipa_ca = CA.IPAServerCA(**self.lib_conf["ca"]["ipa"])

        if self.ipa_ca.is_installed:
            logger.warning("IPA client is already configured on this system.")
            if not force:
                logger.info("Set force argument to True if you want to remove "
                            "previous installation.")
                return
            self.ipa_ca.cleanup()
        else:
            logger.info("IPA client is not configured on the system")
        self.ipa_ca.setup()
        self.sssd_conf.update_default_content()
        self.sssd_conf.set(key="domains",
                           value=f"shadowutils, {self.ipa_ca.domain}",
                           section="sssd")
        dump_to_json(self.ipa_ca)

    def setup_user(self, user_dict: dict, force: bool = False):
        """
        Configures a user on the specified system (either a local machine or an
        IPA server) based on the provided user dictionary.

        :param user_dict: A dictionary containing the user's attributes such as
                          'name', 'passwd', and 'user_type'.
        :type user_dict: dict
        :param force: If ``True``, the user (and associated card directory if
                      applicable) will be re-created, deleting any existing
                      user with the same name.
        :type force: bool
        :return: The created or configured ``User`` object.
        :rtype: SCAutolib.models.user.User
        :raises SCAutolibIPAException: If an IPA user is to be configured but no
                                       IPA client is currently configured on the
                                       system.
        """

        new_user = None

        if user_dict["user_type"] == UserType.local:
            new_user = user.User(username=user_dict["name"],
                                 password=user_dict["passwd"])
            if force:
                new_user.delete_user()
            new_user.add_user()

        else:
            if self.ipa_ca is None:
                msg = "Can't proceed in configuration of IPA user because no " \
                      "IPA Client is configured"
                raise SCAutolibIPAException(msg)
            new_user = user.IPAUser(ipa_server=self.ipa_ca,
                                    username=user_dict["name"],
                                    password=user_dict["passwd"])
            if force:
                new_user.delete_user()
            new_user.add_user()
        self.users.append(new_user)
        dump_to_json(new_user)
        return new_user

    def setup_card(self, card_dict: dict, force: bool = False):
        """
        Creates and initializes a ``Card`` object (either ``PhysicalCard`` or
        ``VirtualCard``) based on the provided card dictionary.
        For virtual cards, this includes preparing SoftHSM2 configuration and
        OpenSSL CNF files, linking the card to its user, and creating the
        SoftHSM2 token and virt_cacard systemd service.

        :param card_dict: A dictionary containing the attributes of the card
                          to be created, such as 'name', 'pin', 'card_type',
                          etc.
        :type card_dict: dict
        :param force: If ``True``, and the card's directory already exists, it
                      will be removed before creating the new card. For virtual
                      cards, it also triggers revocation of existing
                      certificates.
        :type force: bool
        :return: The created ``Card`` object.
        :rtype: SCAutolib.models.card.Card
        :raises NotImplementedError: If a card type other than 'physical' or
                                     'virtual' is specified.
        """

        if card_dict["card_type"] == CardType.physical:
            new_card = card.PhysicalCard(card_dict)
            new_card.user = self.find_card_user(new_card)
            new_card.ca = self.find_card_ca(new_card)
        elif card_dict["card_type"] == CardType.virtual:
            card_dir: Path = Path("/root/cards", card_dict["name"])
            card_dir.mkdir(parents=True, exist_ok=True)

            if force and card_dir.exists():
                rmtree(card_dir)

            hsm_conf = self.prepare_softhsm_config(card_dir)
            new_card = card.VirtualCard(card_dict, softhsm2_conf=hsm_conf.path,
                                        card_dir=card_dir)
            # card needs to know some details of its user
            new_card.user = self.find_card_user(new_card)
            new_card.ca = self.find_card_ca(new_card)
            if new_card.user.user_type == UserType.local:
                new_card.cnf = self.prepare_user_cnf(new_card)
            if force:
                self.revoke_certs(new_card)
            new_card.create()
        else:
            raise NotImplementedError("Other card types than 'physical' and "
                                      "'virtual' are not supported")

        dump_to_json(new_card)
        return new_card

    def find_card_user(self, card: card.Card):
        """
        Links a ``Card`` object to its corresponding ``User`` object based
        on the ``cardholder`` attribute of the card.
        It iterates through the Controller's loaded users to find a match.

        :param card: The ``Card`` object for which to find the associated
                     user.
        :type card: SCAutolib.models.card.Card
        :return: The ``User`` object that matches the card's cardholder.
        :rtype: SCAutolib.models.user.User
        """

        for card_user in self.users:
            if card_user.username == card.cardholder:
                return card_user

        raise SCAutolibNotFound(f"User {card.cardholder} referenced by card "
                                f"{card.name} is not specified in conf!")

    def find_card_ca(self, card: card.Card):
        """
        Links a ``Card`` object to its corresponding ``User`` object based
        on the ``cardholder`` attribute of the card.
        It iterates through the Controller's loaded users to find a match.

        :param card: The ``Card`` object for which to find the associated
                     user.
        :type card: SCAutolib.models.card.Card
        :return: The ``User`` object that matches the card's cardholder.
        :rtype: SCAutolib.models.user.User
        """
        if not card.ca_name:
            return None

        if self.local_ca and card.ca_name == self.local_ca.ca_name:
            return self.local_ca
        elif self.ipa_ca and card.ca_name == self.ipa_ca.ca_name:
            return self.ipa_ca
        else:
            for custom_ca in self.custom_cas:
                if custom_ca.name == card.ca_name:
                    return custom_ca

        raise SCAutolibNotFound(f"CA {card.ca_name} referenced by card "
                                f"{card.name} is not specified in conf!")

    def prepare_softhsm_config(self, card_dir: Path = None):
        """
        Prepares the ``softhsm2.conf`` file specifically for a virtual card.
        This involves creating the configuration file based on a template and
        saving it in the specified card directory.

        :param card_dir: The ``pathlib.Path`` object to the directory where the
                         ``softhsm2.conf`` file should be saved.
        :type card_dir: pathlib.Path, optional
        :return: An initialized ``SoftHSM2Conf`` object.
        :rtype: SCAutolib.models.file.SoftHSM2Conf
        """

        filepath = card_dir.joinpath("sofhtsm2.conf")
        hsm_conf = file.SoftHSM2Conf(filepath, card_dir=card_dir)
        hsm_conf.create()
        hsm_conf.save()
        return hsm_conf

    def prepare_user_cnf(self, card: card.VirtualCard):
        """
        Prepares an OpenSSL configuration file (``{cardholder}.cnf``)
        specifically for a virtual card's user. This CNF file is
        used for generating Certificate Signing Requests (CSRs) for the user's
        certificate.

        :param card: The ``VirtualCard`` object for which to prepare the user
                     CNF.
        :type card: SCAutolib.models.card.VirtualCard
        :return: The ``pathlib.Path`` object to the created user OpenSSL CNF
                 file.
        :rtype: pathlib.Path
        """

        cnf_path = card.card_dir.joinpath(f"{card.cardholder}.cnf")
        cnf = file.OpensslCnf(filepath=cnf_path, conf_type="user",
                              replace=[card.cardholder, card.CN])
        cnf.create()
        cnf.save()
        return cnf.path

    def revoke_certs(self, card: card.VirtualCard):
        """
        Revokes the certificate associated with a virtual card.
        The revocation is performed by the appropriate Certificate Authority
        (local or IPA) based on the user's type.

        :param card: The ``VirtualCard`` object whose certificate needs to be
                     revoked.
        :type card: SCAutolib.models.card.VirtualCard
        :return: None
        """

        if card.cert and card.cert.exists():
            if card.user.user_type == UserType.local:
                self.local_ca.revoke_cert(card.cert)
            else:
                self.ipa_ca.revoke_cert(card.cert)

    def enroll_card(self, card: card.VirtualCard):
        """
        Enrolls a virtual smart card by generating a private key (if missing),
        requesting a certificate from the corresponding CA (local or IPA),
        and then uploading the key and certificate to the virtual card's token.
        The card's URI is also set during this process.

        :param card: The ``VirtualCard`` object to be enrolled.
        :type card: SCAutolib.models.card.VirtualCard
        :return: None
        :raises SCAutolibException: If the card object is not properly
                                    initialized.
        """

        logger.debug(f"Starting enrollment of the card {card.name}")
        if not card:
            raise SCAutolibException(
                f"Card {card.name} is not initialized")

        if not card.key.exists():
            _gen_private_key(card.key)

        if not card.cert.exists():
            csr = card.gen_csr()
            ca = self.ipa_ca \
                if isinstance(card.user, user.IPAUser) else self.local_ca
            card.cert = ca.request_cert(csr, card.cardholder, card.cert)

        card.enroll()
        dump_to_json(card)

    def cleanup(self):
        """
        Cleans up all system configurations and changes made by SCAutolib's
        ``prepare`` command. This includes restoring SSSD
        configuration, deleting created users (except 'root'), removing smart
        cards and their associated directories, and cleaning up both local and
        IPA client CA setups. It also clears OpenSC and SSSD caches.

        :return: None
        """
        virtual_cards = False

        users = {}

        for user_file in LIB_DUMP_USERS.iterdir():
            usr = user.User.load(user_file, ipa_server=self.ipa_ca)
            users[usr.username] = usr
            if usr.username != "root":
                usr.delete_user()

        for card_file in LIB_DUMP_CARDS.iterdir():
            if card_file.exists():
                card_obj = card.Card.load(card_file)
                if card_obj.card_type == CardType.virtual:
                    virtual_cards = True
                    card_obj.user = users[card_obj.cardholder]
                    self.revoke_certs(card_obj)
                card_obj.delete()

        _restore_packages()
        if virtual_cards:
            run(["dnf", "-y", "copr", "--hub", "fedora",
                 "disable", "jjelen/vsmartcard"])

        if self.local_ca:
            self.local_ca.cleanup()
            self.local_ca.restore_ca_db()
        if self.ipa_ca:
            self.ipa_ca.cleanup()
        for custom_ca in self.custom_cas:
            custom_ca.cleanup()

        opensc_cache_dir = Path(os.path.expanduser('~') + "/.cache/opensc/")
        if opensc_cache_dir.exists():
            for cache_file in opensc_cache_dir.iterdir():
                cache_file.unlink()
        logger.debug("Removed opensc file cache")

        sssd_cache_dir = Path(os.path.expanduser('~sssd') + "/.cache/opensc/")
        if sssd_cache_dir.exists():
            for cache_file in sssd_cache_dir.iterdir():
                cache_file.unlink()
        logger.debug("Removed opensc file cache for sssd user")

        # file only created in graphical mode that is why it is removed.
        self.dconf_file.remove()

        self.sssd_conf.restore()
        pcscd_service = File("/usr/lib/systemd/system/pcscd.service")
        pcscd_service.restore()
        opensc_module = File("/usr/share/p11-kit/modules/opensc.module")
        opensc_module.restore()

    @staticmethod
    def _validate_configuration(conf: dict, params: dict = None) -> dict:
        """
        Validates the schema of the provided configuration dictionary against
        predefined schemas for CAs, users, and cards.
        It also accounts for CLI parameters that might override or supplement
        configuration file values.

        :param conf: The configuration data, typically loaded from a JSON file,
                     to be validated.
        :type conf: dict
        :param params: A dictionary of parameters (e.g., from CLI arguments)
                       that might provide missing values or override existing
                       ones in the ``conf`` dictionary.
        :type params: dict, optional
        :return: A dictionary containing the validated and potentially adjusted
                 configuration values.
        :rtype: dict
        :raises schema.SchemaError: If the configuration does not conform to
                                    the defined schemas.
        """

        # FIXME: any schema requires all values to be in the config file, and
        #  only IP address of IPA server is accepted from CLI arguments.
        #  Add loading of the values from params dict
        # IP regex
        # Specify validation schema for CAs

        # Specify general schema for whole config file
        schema = Schema({"root_passwd": Use(str),
                         "ca": schema_cas,
                         "users": [schema_user],
                         "cards": [schema_card]})

        return schema.validate(conf)

    @staticmethod
    def _general_steps_for_virtual_sc():
        """
        Performs general system preparation steps specifically for virtual
        smart cards. This involves configuring the
        ``pcscd`` service and ``opensc.module`` to ensure correct interaction
        with virtual cards. It also adds the ``virt_cacard``
        COPR repository (for Fedora) and cleans SSSD caches.

        :return: None
        """

        _check_selinux()

        pcscd_service = File("/usr/lib/systemd/system/pcscd.service")
        pcscd_service.backup()
        exec_start = pcscd_service.get(section="Service", key="ExecStart")
        if "--auto-exit" in exec_start:
            exec_start = exec_start.replace("--auto-exit", "")
            pcscd_service.set(section="Service", key="ExecStart",
                              value=exec_start)
            pcscd_service.save()

        opensc_module = File("/usr/share/p11-kit/modules/opensc.module")
        opensc_module.backup()
        try:
            opensc_module.get("disable-in", separator=":")
        except SCAutolibWrongConfig:
            logger.warning("OpenSC module does not have option 'disable-in: "
                           "virt_cacard' set")
            opensc_module.set(key="disable-in", value="virt_cacard",
                              separator=": ")
            opensc_module.save()

        run(['systemctl', 'stop', 'pcscd.service', 'pcscd.socket', 'sssd'])
        rmtree("/var/lib/sss/mc/*", ignore_errors=True)
        rmtree("/var/lib/sss/db/*", ignore_errors=True)
        logger.debug(
            "Directories /var/lib/sss/mc/ and /var/lib/sss/db/ removed")

        run("systemctl daemon-reload")
        run("systemctl restart pcscd sssd")

        logger.debug("Copr repo for virt_cacard is enabled")

    @staticmethod
    def _general_steps_for_ipa():
        """
        Performs general system preparation steps for installing an IPA client.
        This includes enabling DNF modules for RHEL 8 and determining the
        correct IPA client package name based on the distribution.

        :return: A list of strings, where each string is the name of an IPA
                 client-related package to be installed.
        :rtype: list
        """

        if isDistro(['rhel', 'centos'], version='8'):
            run("dnf module enable -y idm:DL1")
            run("dnf install @idm:DL1 -y")
            logger.debug("idm:DL1 module is installed")

        if isDistro('fedora'):
            return ["e2fsprogs", "freeipa-client"]
        else:
            return ["e2fsprogs", "ipa-client"]

    def get_user_dict(self, name: str):
        """
        Retrieves a user's configuration dictionary from the loaded
        configuration file based on the provided username.

        :param name: The name of the user to search for in the configuration.
        :type name: str
        :return: A dictionary containing the user's configuration details.
        :rtype: dict
        :raises SCAutolibMissingUserConfig: If a user with the specified name
                                            is not found in the configuration
                                            file.
        """
        for user_dict in self.lib_conf["users"]:
            if user_dict["name"] == name:
                return user_dict
        raise SCAutolibMissingUserConfig(name)

    def init_ca(self, local: bool = False):
        """
        Initializes a Certificate Authority (CA) object based on its type
        (local or IPA). It loads the CA configuration
        from its respective dump file and ensures the CA certificate exists.

        :param local: If ``True``, a local CA is initialized.
                      If ``False``, an IPA server CA is initialized.
        :type local: bool
        :return: None
        :raises SCAutolibMissingCA: If the CA certificate is not found
                                    (for local CA) or if the IPA server CA is
                                    not installed (for IPA CA).
        """

        if local:
            self.local_ca = CA.LocalCA(self.lib_conf["ca"]["local_ca"]["dir"])
            if not self.local_ca.cert.exists():
                raise SCAutolibMissingCA(
                    f"CA certificate not found in {str(self.local_ca.cert)}")
        else:
            self.ipa_ca = CA.IPAServerCA(self.lib_conf["ca"]["ipa"])
            if not self.ipa_ca.is_installed:
                raise SCAutolibMissingCA(
                    "IPA server CA is not installed")
        logger.info("CA is initialized")
