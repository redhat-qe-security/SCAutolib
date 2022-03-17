import subprocess
from configparser import ConfigParser
from os import unlink
from os.path import dirname, join, exists
from pathlib import Path

import pwd
import pytest
import yaml
from SCAutolib.src import env, init_config, LIB_DIR, CONF, LIB_CONF, models
from SCAutolib.src.env import prepare_dirs
import python_freeipa as pipa


@pytest.fixture()
def src_path():
    return dirname(env.__file__)


@pytest.fixture()
def simple_output():
    return "My name is Tom"


@pytest.fixture()
def zero_rc_output(simple_output):
    return f"{simple_output}\nRC:0\n{simple_output}"


@pytest.fixture()
def non_zero_rc_output(simple_output):
    return f"{simple_output}\nRC:256\n{simple_output}"


@pytest.fixture()
def ipa_user():
    return "test-ipa-user"


@pytest.fixture()
def local_user():
    return "test-local-user"


@pytest.fixture()
def create_yaml_content(tmpdir, ipa_user, local_user) -> dict:
    """Create standart content of configuration file in YAML format"""
    card_dir = join(tmpdir, ipa_user)
    content = {
        "root_passwd": "redhat",
        "ca_dir": join(tmpdir, "ca_dir"),
        "ipa_server_root": "redhat",
        "ipa_client_hostname": "ipa-test-client.sc.test.com",
        "ipa_domain": "sc.test.com",
        "ipa_realm": "SC.TEST.COM",
        "ipa_server_admin_passwd": "SECret.123",
        "ipa_server_hostname": "ipa-server.sc.test.com",
        "local_user": {
            "name": local_user,
            "passwd": "654321",
            "pin": "123456",
            "card_dir": join(tmpdir, local_user),
            "local": True
        },
        "ipa_user": {
            "name": ipa_user,
            "passwd": "SECret.123",
            "pin": "123456",
            "card_dir": card_dir,
            "cert": join(card_dir, "cert.pem"),
            "key": join(card_dir, "private.key"),
            "local": False
        }
    }
    return content


@pytest.fixture()
def config_file_correct(tmpdir, create_yaml_content):
    """Create configuration file in YAML format with all required fields."""
    ymal_path = join(tmpdir, "test_configuration.yaml")
    with open(ymal_path, "w") as f:
        yaml.dump(create_yaml_content, f)
    return ymal_path


@pytest.fixture()
def config_file_incorrect(tmpdir, create_yaml_content):
    """Create configuration file in YAML format with missing root_passwd
    field """
    ymal_path = join(tmpdir, "test_configuration.yaml")
    content = create_yaml_content
    content.pop("root_passwd")
    with open(ymal_path, "w") as f:
        yaml.dump(content, f)
    return ymal_path


@pytest.fixture()
def loaded_env(config_file_correct, real_factory, src_path):
    prepare_dirs()
    init_config(config_file_correct)
    return config_file_correct


@pytest.fixture()
def real_factory(tmp_path_factory):
    class Factory:
        _created_dir = list()
        _created_file = list()

        @staticmethod
        def create_dir(dir_path=""):
            if dir_path == "":
                dir_path = tmp_path_factory.mktemp(
                    f"dir-{len(Factory._created_dir)}")
            dir_path.mkdir(exist_ok=True)
            Factory._created_dir.append(dir_path)
            return dir_path

        @staticmethod
        def create_file(dir_name=""):
            if dir_name == "":
                dir_name = Factory.create_dir()
            file_path = f"{dir_name}/file-{len(Factory._created_file)}"
            Path(file_path).touch(exist_ok=True)
            Factory._created_file.append(file_path)
            return file_path

    return Factory


@pytest.fixture()
def ca_dirs(loaded_env):
    """Prepare directories and files needed for local CA deployment"""
    Path(join(LIB_DIR, "ca", "conf")).mkdir(parents=True, exist_ok=True)


@pytest.fixture()
def prep_ca(ca_dirs):
    # TODO: reevaluate neccesaty of this fixture
    """Prepare directories and files needed for local CA deployment"""
    env.create_cnf("ca", conf_dir=join(LIB_DIR, "ca", "conf"))
    env.setup_ca_()


@pytest.fixture(scope="session")
def local_ca(tmp_path_factory):
    ca = models.local_ca.LocalCA(tmp_path_factory.mktemp("local-ca"))
    ca.setup(force=True)
    return ca


@pytest.fixture()
def test_user():
    username = "test-user"
    try:
        pwd.getpwnam(username)
    except KeyError:
        subprocess.check_output(["useradd", username, "-m"])
    user = {"name": username, "local": True}
    return user


@pytest.fixture(scope="function")
def dummy_config(tmpdir):
    conf = join(tmpdir, "dymmu_config.conf")
    cnf = ConfigParser()
    cnf.optionxform = str
    conf_dict = {'first': {"one": "1", "two": 2, "bool": True},
                 "second": {"three": "", "four": "/tmp/"}}
    cnf.read_dict(conf_dict)

    with open(conf, "w") as f:
        cnf.write(f)

    return conf


@pytest.fixture(autouse=True)
def clean_etc():
    """Remove existing library configurations after each test case."""
    yield
    if exists(CONF):
        unlink(CONF)
    if exists(LIB_CONF):
        unlink(LIB_CONF)


@pytest.fixture(scope="function")
def ready_ipa(loaded_env, ipa_ip, ipa_hostname, src_path):
    config_file = loaded_env

    with open(config_file, "r") as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    config["ipa_server_ip"] = ipa_ip
    config["ipa_server_hostname"] = ipa_hostname

    with open(config_file, "w") as f:
        yaml.dump(config, f)

    client_hostname = config["ipa_client_hostname"]
    entry = f"{ipa_ip} {ipa_hostname}"
    domain = config["ipa_domain"]
    realm = config["ipa_realm"]
    admin_passwd = config["ipa_server_admin_passwd"]
    with open("/etc/hosts", "r") as f:
        data = f.read()

    if entry not in data:
        with open("/etc/hosts", "a") as f:
            f.write(f"{entry}\n")

    with open("/etc/resolv.conf", "r") as f:
        data = f.read()
    if f"nameserver {ipa_ip}" not in data:
        data = f"nameserver {ipa_ip}\n" + data
        with open("/etc/resolv.conf", "w") as f:
            f.write(data)

    subprocess.run(["chattr", "-i", "/etc/resolv.conf"])

    subprocess.run(["hostnamectl", "set-hostname", client_hostname,
                    "--static"])

    subprocess.run(["ipa-client-install", "-p", "admin", "--password",
                    admin_passwd, "--server", ipa_hostname, "--domain",
                    domain, "--realm", realm, "--hostname", client_hostname,
                    "--all-ip-addresses", "--force", "--force-join",
                    "--no-ntp", "-U"], input=b"yes")

    subprocess.run(["kinit", "admin"], input=admin_passwd.encode("utf-8"))
    yield config_file

    subprocess.run(["ipa", "host-del", client_hostname, "--updatedns"])
    subprocess.run(["ipa-client-install", "--uninstall", "-U"])


@pytest.fixture()
def ipa_metaclient(ipa_hostname, ipa_passwd):
    client = pipa.ClientMeta(ipa_hostname, verify_ssl=False)
    client.login("admin", ipa_passwd)
    return client
