import logging
import pwd
import subprocess
from configparser import ConfigParser
from os import remove, environ
from os.path import dirname, join, exists, abspath
from pathlib import Path
from shutil import copy
from shutil import copy2
from subprocess import check_output

import pytest
import yaml
from SCAutolib.src import env
from SCAutolib.src import env_logger
from dotenv import load_dotenv
from yaml import dump, load, FullLoader

# create logger with 'spam_application'
logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %('
                              'message)s')
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(ch)


@pytest.fixture()
def src_path():
    return dirname(env.__file__)


@pytest.fixture(autouse=True)
def env_backup(tmpdir, src_path):
    original_env = join(src_path, ".env")
    copied_env = join(tmpdir, ".env-copied")
    if exists(original_env):
        copied_env = copy(original_env, copied_env)

    yield

    if exists(copied_env):
        copy(copied_env, original_env)


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
def env_file(src_path):
    with open(f"{src_path}/.env", "w") as f:
        f.write("")


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
        "ipa_server_hostname": "",
        "local_user": {
            "name": local_user,
            "passwd": "654321",
            "pin": "123456",
            "card_dir": join(tmpdir, local_user),
            "local": True
        },
        "ipa_user": {
            "name": ipa_user,
            "passwd": "654321",
            "pin": "123456",
            "card_dir": card_dir,
            "cert": join(card_dir, "cert.pem"),
            "key": join(card_dir, "private.key"),
            "local": False
        }
    }
    return content


@pytest.fixture(scope="function")
def config_file_correct(tmpdir, create_yaml_content):
    """Create configuration file in YAML format with all required fields."""
    env_logger.debug(f"Directory used in config_file_correct {tmpdir}")
    ymal_path = join(tmpdir, "test_configuration.yaml")
    with open(ymal_path, "w") as f:
        dump(create_yaml_content, f)
    return ymal_path


@pytest.fixture()
def config_file_incorrect(tmpdir, create_yaml_content):
    """Create configuration file in YAML format with missing root_passwd
    field."""
    ymal_path = join(tmpdir, "test_configuration.yaml")
    content = create_yaml_content
    content.pop("root_passwd")
    with open(ymal_path, "w") as f:
        dump(content, f)
    return ymal_path


@pytest.fixture(scope="function")
def loaded_env(config_file_correct, src_path, tmpdir):
    dir_path = ""
    env_logger.debug(f"Directory used in loaded_env {tmpdir}")
    env_file = f"{src_path}/.env"

    if exists(env_file):
        dir_path = tmpdir
        copy2(join(src_path, '.env'), dir_path)

    with open(config_file_correct, "r") as f:
        env_logger.debug(f"Reading configurations from {config_file_correct}")
        data = yaml.load(f, Loader=yaml.FullLoader)
        ca_dir = data["ca_dir"]
    data["restore"] = []

    env_logger.warning(f"Dumping to file {config_file_correct}")
    with open(config_file_correct, "w") as f:
        yaml.dump(data, f)
        env_logger.debug("Restore section is added to te configuration file")

    Path(env_file).unlink()
    with open(env_file, "w") as f:
        f.write(f"TMP={join(ca_dir, 'tmp')}\n")
        f.write(f"KEYS={join(ca_dir, 'tmp', 'keys')}\n")
        f.write(f"CERTS={join(ca_dir, 'tmp', 'certs')}\n")
        f.write(f"BACKUP={join(ca_dir, 'tmp', 'backup')}\n")
        f.write(f"CONF={abspath(config_file_correct)}\n")
        f.write(f"CA_DIR={ca_dir}\n")
    env_logger.debug(f"File {env_file} is created")

    load_dotenv(env_file)
    env_logger.warning(f"Dir in loaded_env {environ['CONF']}")

    ca_dir = environ['CA_DIR']
    for path in ("CA_DIR", "TMP", "CERTS", "KEYS", "BACKUP"):
        Path(environ[path]).mkdir(parents=True, exist_ok=True)
    Path(f"{ca_dir}/conf").mkdir(parents=True, exist_ok=True)
    Path("/var/log/scautolib").mkdir(parents=True, exist_ok=True)

    yield env_file, config_file_correct

    if dir_path != "":
        copy2(join(dir_path, '.env'), join(src_path, '.env'))


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
def prep_ca(loaded_env):
    """Prepare directories and files needed for local CA deployment"""
    env.create_cnf("ca")

    return environ['CA_DIR']


@pytest.fixture()
def prep_ca_real(prep_ca):
    """Prepare directories and files needed for local CA deployment"""
    env.setup_ca_()
    return environ['CA_DIR']


@pytest.fixture()
def clean_conf(loaded_env):
    try:
        yield
    finally:
        load_dotenv(loaded_env[0])
        with open(environ["CONF"], "r") as f:
            data = load(f, Loader=FullLoader)
        data["restore"] = []
        with open(environ["CONF"], "w") as f:
            dump(data, f)


@pytest.fixture()
def test_user():
    username = "test-user"
    try:
        pwd.getpwnam(username)
    except KeyError:
        check_output(["useradd", username, "-m"])
    return username


@pytest.fixture()
def loaded_env_ready(loaded_env):
    env_path = loaded_env[0]
    with open(env_path, "a") as f:
        f.write("READY=1")
    load_dotenv(env_path)
    return env_path, environ["CONF"]


@pytest.fixture()
def remove_env(src_path):
    try:
        yield
    finally:
        remove(join(src_path, ".env"))


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


@pytest.fixture(scope="function")
def ready_ipa(loaded_env, ipa_ip, ipa_hostname, src_path):
    env_path, config_file = loaded_env

    env_logger.warning(f"Path to config file in ready_ipa {environ['CONF']}")

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
