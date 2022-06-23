import pytest
from shutil import copy
from SCAutolib.controller import Controller
from conftest import FILES_DIR
import json


@pytest.fixture()
def dummy_config(tmp_path):
    config_path = f'{tmp_path}/dummy_config_file.json'
    copy(f"{FILES_DIR}/dummy_config_file.json", config_path)
    with open(f"{FILES_DIR}/dummy_config_file.json", "r") as f:
        cnt = f.read()
    with open(config_path, "w") as f:
        f.write(cnt.replace("{path}", str(tmp_path)))

    return config_path


@pytest.fixture()
def wrong_dummy_config(dummy_config):
    with open(dummy_config, "r") as f:
        conf = json.load(f)


def test_parse_config(dummy_config):
    """Test that configuration is parsed and validated properly."""
    cnt = Controller(dummy_config)

    assert cnt.conf_path.is_absolute()
    assert isinstance(cnt.lib_conf, dict)
