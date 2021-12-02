# author: Pavel Yadlouski <pyadlous@redhat.com>
# Unit tests for of SCAutolib.src.utils module
from os import path, system, remove
from shutil import copy

from SCAutolib.src import utils
from SCAutolib.src.exceptions import *
from SCAutolib.test.fixtures import *

CUR_PATH = path.dirname(path.abspath(__file__))
FILES = f"{CUR_PATH}/files"


@pytest.mark.slow()
@pytest.mark.service_restart()
def test_service_restart():
    """Test for restarting the service"""
    rc = utils.restart_service("sssd")
    assert rc == 0
    stat = system("systemctl status sssd")
    assert stat == 0


@pytest.mark.slow()
@pytest.mark.service_restart()
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


def test_gen_cert(prep_ca):
    """Test for generating correct root certificate."""
    cert, key = utils.generate_cert()
    assert path.exists(key)
    assert path.exists(cert)
    remove(key)
    remove(cert)


def test_run_cmd_simple_cmd():
    output = utils.run_cmd("ls -l /")
    assert "var" in output
    assert "RC:0" in output


def test_run_cmd_login_root_with_passwd(test_user):
    output = utils.run_cmd(f"su {test_user['name']}  -c 'su - -c whoami'",
                           pin=False, passwd="redhat")
    assert "root" in output
    assert "RC:0" in output


def test_run_cmd_pattern_not_found_password(test_user):
    with pytest.raises(PatternNotFound):
        utils.run_cmd(f"su {test_user['name']}  -c 'su - -c whoami'",
                      pin=True, passwd="redhat")


def test_check_output_expect(simple_output):
    result = utils.check_output(simple_output, expect=["My", "Tom"])
    assert result


def test_check_output_reject(simple_output):
    with pytest.raises(DisallowedPatternFound):
        utils.check_output(simple_output, reject=["is"])


def test_check_output_pattern_not_found(simple_output):
    with pytest.raises(PatternNotFound):
        utils.check_output(simple_output, expect=["no value"])


def test_check_output_zero_rc(zero_rc_output):
    result = utils.check_output(zero_rc_output, check_rc=True, zero_rc=True)
    assert result


def test_check_output_non_zero_rc_exception(non_zero_rc_output):
    with pytest.raises(NonZeroReturnCode):
        utils.check_output(non_zero_rc_output, check_rc=True, zero_rc=True)


def test_check_output_non_zero_rc_warn(non_zero_rc_output, caplog):
    result = utils.check_output(
        non_zero_rc_output, check_rc=True, zero_rc=False)
    assert "Non zero return code indicated" in caplog.messages
    assert result


def test_check_output_expect_and_zero_rc(zero_rc_output):
    result = utils.check_output(
        zero_rc_output, expect=["Tom", "is"], check_rc=True, zero_rc=True)
    assert result


def test_edit_config(dummy_config, loaded_env):
    utils.edit_config_(dummy_config, section="first", key="one", value="10")

    cnf = ConfigParser()

    with open(dummy_config, "r") as f:
        cnf.read_file(f)

    assert "first" in cnf.sections(), "Section 'first' is not in the sections"
    assert "10" == cnf.get("first", "one")


def test_edit_config_no_section(dummy_config, loaded_env, caplog):
    with pytest.raises(UnknownOption):
        utils.edit_config_(dummy_config, section="no-section", key="one",
                           value="10")
    assert f"Section no-section is not present in config file {dummy_config}" \
           in caplog.messages
