import pytest
from os.path import dirname, join
from os import remove
from SCAutolib.src import env
from SCAutolib.src import load_env
from pathlib import Path
from yaml import dump


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
        "ipa_server_ip": "",
        "ipa_server_hostname": "test-server.domain.com",
        "ipa_client_hostname": "test-client.domain.com",
        "ipa_domain": "domain.com",
        "ipa_realm": "DOMAIN.COM",
        "ipa_server_admin_passwd": "SECret.123",
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
def loaded_env(config_file_correct):
    env_path = load_env(config_file_correct)
    try:
        yield env_path, config_file_correct
    finally:
        remove(env_path)


@pytest.fixture()
def real_factory(tmp_path_factory):
    class Factory:
        _created_dir = list()
        _created_file = list()

        @staticmethod
        def create_dir():
            dir_path = tmp_path_factory.mktemp(f"dir-{len(Factory._created_dir)}")
            dir_path.mkdir(exist_ok=True)
            # assert exists(dir_path)
            Factory._created_dir.append(dir_path)
            return dir_path

        @staticmethod
        def create_file(dir_name=""):
            if dir_name == "":
                dir_name = Factory.create_dir()
            file_path = f"{dir_name}/file-{len(Factory._created_file)}"
            Path(file_path).touch(exist_ok=True)
            # assert exists(file_path)
            Factory._created_file.append(file_path)
            return file_path

    return Factory
