import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
from schema import Schema, Use, Or, And, Optional
from shutil import rmtree
from typing import Union

from SCAutolib import logger, run
from SCAutolib.exceptions import SCAutolibWrongConfig, SCAutolibException
from SCAutolib.models import CA, file, user, card


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
        self.lib_conf = self._validate_schema(params)

    def prepare(self):
        """
        Method for setting up whole system based on configuration file and CLI commands
        :return:
        """
        ...

    @property
    def conf_path(self):
        return self._lib_conf_path

    def setup_system(self):
        """
        This method would set up whole system for smart card testing.
        """

        # Update SSSD with values for local users
        ...

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

        self.local_ca = CA.LocalCA(dir=ca_dir, cnf=cnf,)
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
        self.users.append(new_user)

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
                self._gen_private_key(user_.key)

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

    def _general_steps_for_virtual_sc(self):
        """
        Prepare the system for virtual smart card
        """
        # TODO: This steps should be done in the Controller
        with open("/usr/lib/systemd/system/pcscd.service", "r+") as f:
            data = f.read().replace("--auto-exit", "")
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

    def _gen_private_key(self, key_path: Path):
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

    def _validate_schema(self, params: {}):
        """
        Validate schema of the configuration file. If some value doesn't present
        in the config file, this value would be looked in the CLI parameters

        :param params: CLI arguments
        :return:
        """
        # FIXME: no schema requires all values to be in the config file, and
        #  only IP address of IPA server is accepted from CLI arguments.
        # IP regex
        # Specify validation schema for CAs
        schema_cas = Schema(And(
            Use(dict),
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
