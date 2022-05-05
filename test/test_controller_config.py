import pytest
from shutil import copy
from SCAutolib.controller import Controller
from conftest import FILES_DIR
import yaml
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


@pytest.mark.ipa
def test_parse_config(dummy_config):
    cnt = Controller(dummy_config, {"ip_addr": None})

    assert cnt.conf_path.is_absolute()
    assert isinstance(cnt.lib_conf, dict)

    assert cnt.local_ca is not None
    assert cnt.ipa_ca._ipa_server_ip is None
    assert cnt.ipa_ca is not None
