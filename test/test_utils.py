import pytest
from SCAutolib.src import utils
from shutil import copy
from os import path, system, remove

CUR_PATH = path.dirname(path.abspath(__file__))
FILES = f"{CUR_PATH}/files"


def test_service_restart():
    """Test for restarting the service"""
    rc = utils.restart_service("sssd")
    assert rc == 0
    stat = system("systemctl status sssd")
    assert stat == 0


def test_service_restart_fail():
    """Test for fault of service restart."""
    copy(f"{FILES}/test.service", "/etc/systemd/system/test.service")
    rc = system("systemctl daemon-reload")
    assert rc == 0
    rc = utils.restart_service("test")
    assert rc != 0
    remove("/etc/systemd/system/test.service")
    rc = system("systemctl daemon-reload")
    assert rc == 0


def test_gen_cer():
    """Test for generating correct root certificate."""
    cert, key = utils.generate_root_ca_crt()
    assert path.exists(key)
    assert path.exists(cert)
    remove(key)
    remove(cert)
