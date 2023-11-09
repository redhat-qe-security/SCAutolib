import json
from pathlib import Path
from schema import Schema, Use
from shutil import rmtree
from typing import Union

from SCAutolib import exceptions, schema_cas, schema_user
from SCAutolib import (logger, run, LIB_DIR, LIB_BACKUP, LIB_DUMP,
                       LIB_DUMP_USERS, LIB_DUMP_CAS, LIB_DUMP_CARDS,
                       TEMPLATES_DIR)
from SCAutolib.models import CA, file, user, card, authselect as auth
from SCAutolib.models.file import File
from SCAutolib.utils import (OSVersion, _check_selinux, _gen_private_key,
                             _get_os_version, _install_packages,
                             _check_packages, dump_to_json, local_ca_factory)


class Controller:
    authselect: auth.Authselect = auth.Authselect()
    sssd_conf: file.SSSDConf = file.SSSDConf()
    lib_conf: dict = None
    _lib_conf_path: Path = None
    local_ca: CA.LocalCA = None
    ipa_ca: CA.IPAServerCA = None
    users: [user.User] = None
    dconf_file = File(filepath='/etc/dconf/db/local.d/gnome_disable_welcome',
                      template=Path(TEMPLATES_DIR, 'gnome_disable_welcome'))

    @property
    def conf_path(self):
        return self._lib_conf_path

    def __init__(self, config: Union[Path, str], params: {} = None):
        """
        Constructor will parse and check input configuration file. If some
        required fields in the configuration are missing, CLI parameters
        would be checked if missing values are there. If not, an exception
        would be raised. After parsing the configuration file and filling
        internal values of the Controller object, other related objects (users,
        cards, CAs, Authselect, etc.) would be initialised, but any real action
        that would affect the system
        wouldn't be made.

        :param config: Path to configuration file with metadata for testing.
        :type config: pathlib.Path or str
        :param params: Parameters from CLI
        :type params: dict
        :return:
        """

        # Check params

        # Parse config file
        self._lib_conf_path = config.absolute() if isinstance(config, Path) \
            else Path(config).absolute()

        with self._lib_conf_path.open("r") as f:
            tmp_conf = json.load(f)
            if tmp_conf is None:
                raise exceptions.SCAutolibException(
                    "Data are not loaded correctly.")
        self.lib_conf = self._validate_configuration(tmp_conf, params)
        self.users = []
        for d in (LIB_DIR, LIB_BACKUP, LIB_DUMP, LIB_DUMP_USERS, LIB_DUMP_CAS,
                  LIB_DUMP_CARDS):
            d.mkdir(exist_ok=True)

    def prepare(self, force: bool, gdm: bool, install_missing: bool,
                graphical: bool):
        """
        Method for setting up whole system based on configuration file and
        CLI commands
        """
        self.setup_system(install_missing, gdm, graphical)

        # In this method not having section for local CA and/or for IPA CA is OK
        try:
            self.setup_local_ca(force=force)
        except exceptions.SCAutolibWrongConfig as e:
            logger.info(e)
        try:
            self.setup_ipa_client(force=force)
        except exceptions.SCAutolibWrongConfig as e:
            logger.info(e)
        for usr in self.lib_conf["users"]:
            u = self.setup_user(usr, force=force)
            self.enroll_card(u)

    def setup_system(self, install_missing: bool, gdm: bool, graphical: bool):
        """
        Do general system setup meaning package installation based on
        specifications in the configuration file, SSSD configuration,
        configurations for virtual smart cards, etc.

        :param install_missing: If True, all missing packages would be
            installed
        :type install_missing: bool
        :param gdm: If True, GDM package would be installed
        :type gdm: bool
        :return:
        """
        for d in (LIB_DIR, LIB_BACKUP, LIB_DUMP, LIB_DUMP_USERS, LIB_DUMP_CAS,
                  LIB_DUMP_CARDS):
            d.mkdir(exist_ok=True)

        packages = ["opensc", "httpd", "sssd", "sssd-tools", "gnutls-utils"]
        if gdm:
            packages.append("gdm")

        if graphical:
            # ffmpeg-free is in EPEL repo
            packages += ["tesseract", "ffmpeg-free"]

        # Prepare for virtual cards
        if "virtual" in [u["card_type"] for u in self.lib_conf["users"]]:
            packages += ["pcsc-lite-ccid", "pcsc-lite", "virt_cacard",
                         "vpcd", "softhsm"]
            run("dnf -y copr enable jjelen/vsmartcard")

        # Add IPA packages if needed
        if not all([u["local"] for u in self.lib_conf["users"]]):
            packages += self._general_steps_for_ipa()

        # Check for installed packages
        missing = _check_packages(packages)
        if install_missing and missing:
            _install_packages(missing)
        elif missing:
            msg = "Can't continue. Some packages are missing: " \
                  f"{', '.join(missing)}"
            logger.critical(msg)
            raise exceptions.SCAutolibException(msg)

        if graphical:
            run(['dnf', 'groupinstall', 'Server with GUI', '-y'])
            # disable subscription message
            run(['systemctl', '--global', 'mask',
                 'org.gnome.SettingsDaemon.Subscription.target'])
            # disable welcome message
            self.dconf_file.create()
            self.dconf_file.save()
            run('dconf update')

        run(['dnf', 'groupinstall', "Smart Card Support", '-y'])
        logger.debug("Smart Card Support group in installed.")

        self.sssd_conf.create()
        self.sssd_conf.save()
        self._general_steps_for_virtual_sc()

        base_user = user.BaseUser("base-user", "redhat")
        base_user.add_user()
        dump_to_json(base_user)
        dump_to_json(user.BaseUser(username="root",
                                   password=self.lib_conf["root_passwd"]))

    def setup_local_ca(self, force: bool = False):
        """
        Setup local CA based on configuration from the configuration file. All
        necessary file for this operation (e.g. CNF file for self-signed root
        certificate) would be created along the way.

        :param force: If local CA already exists in given directory, specifies
            if it should be overwritten
        :type force: bool
        :raises: SCAutolib.exceptions.SCAutolibWrongConfig
        """

        if "local_ca" not in self.lib_conf["ca"]:
            msg = "Section for local CA is not found in the configuration file"
            raise exceptions.SCAutolibWrongConfig(msg)

        ca_dir: Path = self.lib_conf["ca"]["local_ca"]["dir"]
        self.local_ca = local_ca_factory(ca_dir, force)
        logger.info(f"Local CA is configured in {ca_dir}")

        dump_to_json(self.local_ca)

    def setup_ipa_client(self, force: bool = False):
        """
        Configure IPA client for given IPA server on current host. IPA server
        should be already up and running for correct configuration of the IPA
        client

        :param force: If IPA Client is already configured on the system,
            specifies if it should be removed before configuring a new client.
        :type force: bool
        :raises: SCAutolib.exceptions.SCAutolibWrongConfig
        """
        if "ipa" not in self.lib_conf["ca"]:
            msg = "Section for IPA is not found in the configuration file"
            raise exceptions.SCAutolibWrongConfig(msg)
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
        Configure the user on the specified system (local machine/CA). The user
        would be configured along with the card based on configurations.

        :param force: specify if the user should be re-created with its
            card directory
        :type force: bool
        :param user_dict: set of values to initialise the user
        :type user_dict: dict
        :return: the user object
        """
        new_user = None
        card_dir: Path = user_dict["card_dir"]
        # Card dir is home dir of the user home directory
        if force and card_dir.exists():
            rmtree(card_dir)

        if user_dict["local"]:
            new_user = user.User(username=user_dict["name"],
                                 pin=user_dict["pin"],
                                 password=user_dict["passwd"],
                                 card_dir=card_dir,
                                 cert=user_dict["cert"], key=user_dict["key"],
                                 local=True)
            if force:
                if new_user.cert and new_user.cert.exists():
                    self.local_ca.revoke_cert(new_user.cert)
                new_user.delete_user()
            user_dict["card_dir"].mkdir(exist_ok=True)
            new_user.add_user()

            csr_path = new_user.card_dir.joinpath(f"csr-{new_user.username}.csr")
            cnf = file.OpensslCnf(filepath=csr_path, conf_type="user",
                                  replace=new_user.username)
            cnf.create()
            cnf.save()

            new_user.cnf = cnf.path
            self.sssd_conf.set(
                section=f"certmap/shadowutils/{new_user.username}",
                key="matchrule",
                value=f"<SUBJECT>.*CN={new_user.username}.*")
            self.sssd_conf.save()
            self.sssd_conf.update_default_content()
            run(["systemctl", "restart", "sssd"])
            logger.debug(f"Match rule for user {new_user.username} is added "
                         f"to /etc/sssd/sssd.conf")
        else:
            if self.ipa_ca is None:
                msg = "Can't proceed in configuration of IPA user because no " \
                      "IPA Client is configured"
                raise exceptions.SCAutolibException(msg)
            new_user = user.IPAUser(ipa_server=self.ipa_ca,
                                    username=user_dict["name"],
                                    pin=user_dict["pin"],
                                    password=user_dict["passwd"],
                                    card_dir=card_dir,
                                    cert=user_dict["cert"],
                                    key=user_dict["key"],
                                    local=False)
            if force:
                if new_user.cert and new_user.cert.exists():
                    self.ipa_ca.revoke_cert(new_user.cert)
                new_user.delete_user()
            user_dict["card_dir"].mkdir(exist_ok=True)

            new_user.add_user()

        if user_dict["card_type"] == "virtual":
            hsm_conf = file.SoftHSM2Conf(
                new_user.card_dir.joinpath("sofhtsm2.conf"),
                new_user.card_dir)
            hsm_conf.create()
            hsm_conf.save()

            new_user.card = card.VirtualCard(new_user,
                                             softhsm2_conf=hsm_conf.path)
        else:
            raise NotImplementedError("Other card type than 'virtual' does"
                                      "not supported yet")

        new_user.card.create()
        self.users.append(new_user)

        dump_to_json(new_user)

        return new_user

    def enroll_card(self, user_: user.User, force: bool = False):
        """
        Enroll the card of a given user with configured CA. If private key
        and/or the certificate do not exists, new one's would be requested
        from corresponding CA.

        :param force:
        :param user_: User with a card to be enrolled.
        """
        logger.debug(f"Starting enrollment of the card for user "
                     f"{user_.username}")
        if not user_.card:
            raise exceptions.SCAutolibException(
                f"Card for the user {user_.username} is not initialized")

        if not user_.key.exists():
            _gen_private_key(user_.key)

        if not user_.cert.exists():
            # Creating a new private key makes sense only if the certificate
            # doesn't exist yet

            csr = user_.gen_csr()

            ca = self.ipa_ca \
                if isinstance(user_, user.IPAUser) else self.local_ca
            user_.cert = ca.request_cert(csr, user_.username, user_.cert)

        user_.card.enroll()

        dump_to_json(user_.card)
        # Update the dump for current user to link it with the card
        dump_to_json(user_)

    def cleanup(self):
        """
        Clean the system after setup. This method restores the SSSD config file,
        deletes created users with cards, remove CA's (local and/or IPA Client)
        """
        self.sssd_conf.clean()

        for user_file in LIB_DUMP_USERS.iterdir():
            usr = user.BaseUser.load(user_file)
            usr.delete()
            card_file = LIB_DUMP_CARDS.joinpath(f"card-{usr.username}.json")
            if card_file.exists():
                card.Card.load(card_file, user=user).delete()

        if self.local_ca:
            self.local_ca.cleanup()
        if self.ipa_ca:
            self.ipa_ca.cleanup()

        self.authselect.cleanup()

    @staticmethod
    def _validate_configuration(conf: dict, params: {} = None) -> dict:
        """
        Validate schema of the configuration file. If some value is not present
        in the config file, this value would be looked in the CLI parameters

        :param conf: Configuration to be parsed (e.g. data loaded from
            JSON file)
        :type conf: dict
        :param params: CLI arguments
        :type params: dict
        :return: dictionary with parsed values from conf and params attributes.
            All values are retyped to specified type.
        :rtype: dict
        """
        # FIXME: any schema requires all values to be in the config file, and
        #  only IP address of IPA server is accepted from CLI arguments.
        #  Add loading of the values from params dict
        # IP regex
        # Specify validation schema for CAs

        # Specify general schema for whole config file
        schema = Schema({"root_passwd": Use(str),
                         "ca": schema_cas,
                         "users": [schema_user]})

        return schema.validate(conf)

    @staticmethod
    def _general_steps_for_virtual_sc():
        """
        Prepare the system for virtual smart card. Preparation means to
        configure pcscd service and opensc module to work correctly
        with virtual smart card. Also, repository for installing virt_cacard
        package is added in this method.
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
        except exceptions.SCAutolibException:
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
        General system preparation for installing IPA client on RHEL/Fedora

        :return: name of the IPA client package for current Linux
        """
        os_version = _get_os_version()
        if os_version not in (OSVersion.RHEL_9, OSVersion.CentOS_9):
            run("dnf module enable -y idm:DL1")
            run("dnf install @idm:DL1 -y")
            logger.debug("idm:DL1 module is installed")

        if os_version == OSVersion.Fedora:
            return ["freeipa-client"]
        else:
            return ["ipa-client"]

    def get_user_dict(self, name):
        """
        Get user dictionary from the config file.

        :param name: name of the user
        :type name: str
        :return: user dictionary
        :rtype: dict
        """
        for user_dict in self.lib_conf["users"]:
            if user_dict["name"] == name:
                return user_dict
        raise exceptions.SCAutolibMissingUserConfig(name)

    def init_ca(self, local: bool = False):
        """
        Initialize CA.

        :param local: if True, local CA is initialized, otherwise IPA
        :type local: bool
        """
        if local:
            self.local_ca = CA.LocalCA(self.lib_conf["ca"]["local_ca"]["dir"])
            if not self.local_ca.cert.exists():
                raise exceptions.SCAutolibMissingCA(
                    f"CA certificate not found in {str(self.local_ca.cert)}")
        else:
            self.ipa_ca = CA.IPAServerCA(self.lib_conf["ca"]["ipa"])
            if not self.ipa_ca.is_installed:
                raise exceptions.SCAutolibMissingCA(
                    "IPA server CA is not installed")
        logger.info("CA is initialized")
