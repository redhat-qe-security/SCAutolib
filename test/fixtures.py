import pytest
from os.path import dirname, join
from os import remove
from SCAutolib.src import env
from SCAutolib.src import load_env
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
def yaml_file_correct(tmpdir, create_yaml_content):
    ymal_path = join(tmpdir, "test_configuration.yaml")
    with open(ymal_path, "w") as f:
        dump(create_yaml_content, f)
    return ymal_path


@pytest.fixture()
def yaml_file_incorrect(tmpdir, create_yaml_content):
    ymal_path = join(tmpdir, "test_configuration.yaml")
    content = create_yaml_content
    content.pop("root_passwd")
    with open(ymal_path, "w") as f:
        dump(content, f)
    return ymal_path


@pytest.fixture()
def config_file_coorect(yaml_file_correct):
    env_path = load_env(yaml_file_correct)
    try:
        yield env_path
    except Exception as e:
        raise e
    finally:
        remove(env_path)


@pytest.fixture()
def config_file_incorrect(yaml_file_incorrect):
    env_path = load_env(yaml_file_incorrect)
    try:
        yield env_path
    except Exception as e:
        raise e
    finally:
        remove(env_path)
