import json
from pathlib import Path
from schema import Schema, Use, Or, And, Optional
from shutil import rmtree
from typing import Union

from SCAutolib import logger, run, LIB_DIR, LIB_BACKUP
from SCAutolib.exceptions import SCAutolibWrongConfig, SCAutolibException
from SCAutolib.models import CA, file, user, card
from SCAutolib.utils import OSVersion, _check_selinux, _gen_private_key, _get_os_version, _install_packages, \
    _check_packages


class Controller:
    # authselect: authselect.Authselect = authselect.Authselect()
    sssd_conf: file.SSSDConf = file.SSSDConf()
    lib_conf: dict = None
    _lib_conf_path: Path = None
    local_ca: CA.LocalCA = None
    ipa_ca: CA.IPAServerCA = None
    users: [user.User] = None

    @property
    def conf_path(self):
        return self._lib_conf_path

    def __init__(self, config: Union[Path, str], params: {}):
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
            self.lib_conf = json.load(f)
            assert self.lib_conf, "Data are not loaded correctly."
        self.lib_conf = self._validate_configuration(params)

    def prepare(self):
        """
        Method for setting up whole system based on configuration file and
        CLI commands

        :return:
        """
        ...

    def setup_system(self, install_missing: bool, gdm: bool):
        """
        Do general system setup meaning package installation based on
        specifications in the configuration file, SSSD configuration,
        configurations for virtual smart cards, etc.

        :param install_missing: If True, all missing packages would be
            installed
        :type install_missing:
        :param gdm: If True, GDM package would be installed
        :type gdm: bool
        :return:
        """
        LIB_DIR.mkdir()
        LIB_BACKUP.mkdir()

        packages = ["opensc", "httpd", "sssd", "sssd-tools"]
        if gdm:
            packages.append("gdm")

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
        if install_missing:
            _install_packages(missing)

        run(['dnf', 'groupinstall', "Smart Card Support", '-y'])
        logger.debug("Smart Card Support group in installed.")

        self.sssd_conf.create()
        self.sssd_conf.save()
        self._general_steps_for_virtual_sc()

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

        if "local_ca" not in self.lib_conf["ca"].keys():
            msg = "Section for local CA is not found in the configuration file"
            raise SCAutolibWrongConfig(msg)

        ca_dir = self.lib_conf["ca"]["local_ca"]["dir"]
        ca_dir.mkdir(exist_ok=True)
        cnf = file.OpensslCnf(ca_dir, "CA", str(ca_dir))

        self.local_ca = CA.LocalCA(dir=ca_dir, cnf=cnf, )
        self.local_ca.cnf.create()
        self.local_ca.cnf.save()

        self.local_ca.setup(force)
        # Generate certificates

    def setup_ipa_ca(self, force: bool = False):
        """
        Configure IPA client for given IPA server on current host. IPA server
        should be already up and running for correct configuration of the IPA
        client

        :param force: If IPA Client is already configured on the system,
            specifies if it should be removed before configuring a new client.
        :type force: bool
        :raises: SCAutolib.exceptions.SCAutolibWrongConfig
        """
        if "ipa" not in self.lib_conf["ca"].keys():
            msg = "Section for IPA is not found in the configuration file"
            raise SCAutolibWrongConfig(msg)
        self.ipa_ca = CA.IPAServerCA(**self.lib_conf["ca"]["ipa"])
        self.ipa_ca.setup(force=force)

    def setup_user(self, user_dict):
        """
        Configure the user on the specified system (local machine/CA). The user
        would be configured along with the card based on configurations.

        :param user_dict:
        :return:
        """
        if user_dict["local"]:
            new_user = user.User(username=user_dict["name"],
                                 pin=user_dict["pin"],
                                 password=user_dict["passwd"],
                                 card_dir=user_dict["card_dir"],
                                 cert=user_dict["cert"], key=user_dict["key"])
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
            logger.debug(f"Match rule for user {new_user.username} is added "
                         f"to /etc/sssd/sssd.conf")
        else:
            if self.ipa_ca is None:
                msg = "Can't proceed in configuration of IPA user because no " \
                      "IPA Client is configured"
                raise SCAutolibException(msg)
            new_user = user.IPAUser(ipa_server=self.ipa_ca,
                                    username=user_dict["name"],
                                    pin=user_dict["pin"],
                                    password=user_dict["passwd"],
                                    card_dir=user_dict["card_dir"],
                                    cert=user_dict["cert"],
                                    key=user_dict["key"])

        new_user.add_user()
        new_card = None
        if user_dict["card_type"] == "virtual":
            hsm_conf = file.SoftHSM2Conf(new_user.card_dir, new_user.card_dir)
            hsm_conf.create()

            new_card = card.VirtualCard()
            new_card.softhsm2_conf = hsm_conf
        else:
            raise NotImplementedError("Other card type than 'virtual' does not "
                                      "supported yet")

        new_user.card = new_card

    def enroll_card(self, user_: user.User):
        """
        Enroll the card of a given user with configured CA. If private key
        and/or the certificate are not exists, new one's would be requested
        from corresponding CA.

        :param user_: User with a card to be enrolled.
        """
        if not user_.card:
            raise SCAutolibException(f"Card for the user {user_.username} does "
                                     f"not initialized")
        if user_.cert is None:
            # Creating a new private key makes sense only if the certificate
            # doesn't exist yet
            if user_.key is None:
                user_.key = user_.card_dir.joinpath("private.key")
                _gen_private_key(user_.key)

            csr = user_.gen_csr()
            if user_.cert is None:
                user_.cert = user_.card_dir.joinpath(
                    f"cert-{user_.username}.pem")

            if isinstance(user_, user.IPAUser):
                self.ipa_ca.request_cert(csr, user_.username, user_.cert)
            else:
                self.local_ca.request_cert(csr, user_.username, user_.cert)

        user_.card.enroll()

    def cleanup(self):
        ...

    def _validate_configuration(self, params: {}):
        """
        Validate schema of the configuration file. If some value doesn't present
        in the config file, this value would be looked in the CLI parameters

        :param params: CLI arguments
        :return:
        """
        # FIXME: any schema requires all values to be in the config file, and
        #  only IP address of IPA server is accepted from CLI arguments.
        #  Add loading of the values from params dict
        # IP regex
        # Specify validation schema for CAs
        schema_cas = Schema(And(
            Use(dict),
            # Check that CA section contains at least one and maximum
            # two entries
            lambda l: 1 <= len(l.keys()) <= 2,
            {Optional("local_ca"): {"dir": Use(Path)},
             Optional("ipa"): {
                 'admin_passwd': Use(str),
                 'root_passwd': Use(str),
                 Optional('ip_addr', default=params["ip_addr"]): Use(str),
                 'server_hostname': Use(str),
                 'client_hostname': Use(str),
                 'domain': Use(str),
                 'realm': Use(str.upper)}}),
            ignore_extra_keys=True)

        # Specify validation schema for all users
        schema_user = Schema({'name': Use(str),
                              'passwd': Use(str),
                              'pin': Use(str),
                              Optional('card_dir', default=None): Use(Path),
                              'card_type': Or("virtual", "real", "removinator"),
                              Optional('cert', default=None): Use(Path),
                              Optional('key', default=None): Use(Path),
                              'local': Use(bool)})

        # Specify general schema for whole config file
        schema = Schema({"root_passwd": Use(str),
                         "ca": schema_cas,
                         "users": [schema_user]})

        return schema.validate(self.lib_conf)

    @staticmethod
    def _general_steps_for_virtual_sc():
        """
        Prepare the system for virtual smart card. Preparation means to
        configure pcscd service and opensc module to be able correctly working
        with virtual smart card. Also, repository for installing virt_cacard
        package is added in this method.
        """

        _check_selinux()
        with open("/usr/lib/systemd/system/pcscd.service", "w+") as f:

            data = f.read().replace("--auto-exit", "")
            if "--auto-exit" in data:
                f.write(data.replace("--auto-exit", ""))
            else:
                f.write(data)

        with open("/usr/share/p11-kit/modules/opensc.module", "r+") as f:
            data = f.read()
            if "disable-in: virt_cacard" not in data:
                f.write("disable-in: virt_cacard\n")
                logger.debug("opensc.module is updated")

        run(['systemctl', 'stop', 'pcscd.service', 'pcscd.socket', 'sssd'])
        rmtree("/var/lib/sss/mc/*", ignore_errors=True)
        rmtree("/var/lib/sss/db/*", ignore_errors=True)
        logger.debug(
            "Directories /var/lib/sss/mc/ and /var/lib/sss/db/ removed")

        run("systemctl daemon-reload")
        run("systemctl restart pcscd sssd")

        run("dnf -y copr enable jjelen/vsmartcard")
        logger.debug("Copr repo for virt_cacard is enabled")

    @staticmethod
    def _general_steps_for_ipa():
        """
        General system preparation for installing IPA client on RHEL/Fedora

        :return: name of the IPA client package for current Linux
        """
        os_version = _get_os_version()
        if os_version != OSVersion.RHEL_9:
            run("dnf module enable -y idm:DL1")
            run("dnf install @idm:DL1 -y")
            logger.debug("idm:DL1 module is installed")

        if os_version == OSVersion.Fedora:
            return ["freeipa-client"]
        else:
            return ["ipa-client"]
