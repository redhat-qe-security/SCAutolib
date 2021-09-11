import pwd
from configparser import ConfigParser
from os import remove, environ
from os.path import dirname, join
from pathlib import Path
from subprocess import check_output

import pytest
from SCAutolib.src import load_env, env
from dotenv import load_dotenv
from yaml import dump, load, FullLoader


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
            "passwd": "654321",
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
        dump(create_yaml_content, f)
    return ymal_path


@pytest.fixture()
def config_file_incorrect(tmpdir, create_yaml_content):
    """Create configuration file in YAML format with missing root_passwd field"""
    ymal_path = join(tmpdir, "test_configuration.yaml")
    content = create_yaml_content
    content.pop("root_passwd")
    with open(ymal_path, "w") as f:
        dump(content, f)
    return ymal_path


@pytest.fixture()
def loaded_env(config_file_correct, real_factory, remove_env):
    env_path = load_env(config_file_correct)
    load_dotenv(env_path)
    ca_dir = environ['CA_DIR']
    for dir_path in ("CA_DIR", "TMP", "CERTS", "KEYS", "BACKUP"):
        real_factory.create_dir(Path(environ[dir_path]))
    real_factory.create_dir(Path(f"{ca_dir}/conf"))
    real_factory.create_dir(Path("/var/log/scautolib"))

    return env_path, config_file_correct


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
