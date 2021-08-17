from SCAutolib.src.env import *
from SCAutolib.src.exceptions import *
from configparser import ConfigParser
from os import stat, mkdir, remove
from os.path import isfile, join
from shutil import rmtree, copyfile
import re
from pytest import raises
from SCAutolib.test.fixtures import *


def test_create_sssd_config(tmpdir):
    """Check correct creation og sssd.conf with basic sections and permission."""
    sssd_conf = "/etc/sssd/sssd.conf"
    backp_sssd_conf = join(tmpdir, "sssd.conf")
    copyfile(sssd_conf, backp_sssd_conf)

    create_sssd_config()
    cnf = ConfigParser()
    cnf.optionxform = str
    with open(sssd_conf, "r") as file:
        cnf.read_file(file)
    sections = cnf.sections()
    perms = oct(stat(sssd_conf).st_mode & 0o777)
    try:
        assert "sssd" in sections
        assert "pam" in sections
        assert "nss" in sections
        assert "domain/shadowutils" in sections
        assert perms == oct(0o600), "wrong permission on sssd.conf"
    finally:
        copyfile(backp_sssd_conf, sssd_conf)


def test_create_cnf():
    username = "test-user"
    conf_dir = "/tmp/test-user"

    mkdir(conf_dir)
    create_cnf(username, conf_dir)
    try:
        assert isfile(join(conf_dir, f"req_{username}.cnf"))
    finally:
        rmtree(conf_dir)


def test_create_cnf_ca():
    username = "ca"
    ca_dir = "/tmp/ca"
    conf_dir = "/tmp/ca/conf"
    ca_cnf = join(conf_dir, f"ca.cnf")

    mkdir(ca_dir)
    mkdir(conf_dir)
    create_cnf(username, conf_dir, ca_dir)
    try:
        assert isfile(ca_cnf)

        with open(ca_cnf, "r") as f:
            content = f.read()
        assert re.findall(f"dir[ ]*=[ ]*{ca_dir}", content)
    finally:
        rmtree(ca_dir)


def test_create_cnf_exception():
    username = "test-user"

    with raises(UnspecifiedParameter):
        create_cnf(username)


def test_create_softhsm2_config():
    card_dir = "/tmp/card-dir"
    conf_dir = join(card_dir, "conf")
    softhsm2_config = join(conf_dir, "softhsm2.conf")
    mkdir(card_dir)
    mkdir(conf_dir)
    create_softhsm2_config(card_dir)
    try:
        assert isfile(softhsm2_config)
        with open(softhsm2_config, "r") as f:
            content = f.read()
        assert re.findall(f"directories.tokendir[ ]*=[ ]*{card_dir}/tokens/", content)
    finally:
        rmtree(card_dir)


def test_create_virt_card_service():
    username = "test-user"
    service_path = f"/etc/systemd/system/virt_cacard_{username}.service"
    card_dir = "/tmp/card-dir"
    conf_dir = f"{card_dir}/conf"
    mkdir(card_dir)
    mkdir(conf_dir)
    cnf = ConfigParser()
    create_virt_card_service(username, card_dir)

    with open(service_path, "r") as f:
        cnf.read_file(f)

    assert isfile(service_path)
    assert f"SOFTHSM2_CONF=\"{conf_dir}/softhsm2.conf\"" == cnf.get("Service", "Environment")
    assert f"{card_dir}" == cnf.get("Service", "WorkingDirectory")
    assert f"virtual card for {username}" == cnf.get("Unit", "Description")

    rmtree(card_dir)
    remove(service_path)


def test_check_config_true(config_file_coorect, caplog):
    result = check_config()
    assert result
    assert "Configuration file is OK." in caplog.messages


def test_check_config_false(config_file_incorrect, caplog):
    result = check_config()
    assert not result
    assert "Configuration file is OK." not in caplog.messages
    assert "Field root_passwd is not present in the config." in caplog.messages
