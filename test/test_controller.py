import pytest
from configparser import ConfigParser
from subprocess import check_output

from SCAutolib.controller import Controller


@pytest.fixture()
def controller(dummy_config):
    return Controller(dummy_config)


def test_parse_config(dummy_config):
    """Test that configuration is parsed and validated properly."""
    cnt = Controller(dummy_config)

    assert cnt.conf_path.is_absolute()
    assert isinstance(cnt.lib_conf, dict)


@pytest.mark.service_restart
def test_setup_system(controller):
    cnt: Controller = controller
    packages = ["opensc", "httpd", "sssd", "sssd-tools", "gnutls-utils",
                "pcsc-lite-ccid", "pcsc-lite", "virt_cacard", "vpcd",
                "softhsm"]

    check_output(["dnf", "remove", "softhsm", "-y"], encoding="utf8")

    cnt.setup_system(install_missing=True, gdm=False)

    for p in packages:
        out = check_output(["rpm", "-qa", p], encoding="utf-8")
        assert p in out
    current_sssd = ConfigParser()
    with open("/etc/sssd/sssd.conf", "r") as f:
        current_sssd.read_file(f)

    msg = "Current SSSD conf content is different from config parser object " \
          "in the controller"
    assert set(current_sssd.sections()).issubset(set(
        cnt.sssd_conf._default_parser.sections())), msg


@pytest.mark.ipa
def test_users_create_and_delete(controller, tmp_path, ipa_fixture):
    """Test for adding local and IPA users to the systems and initializing all
    required files."""
    cnt: Controller = controller
    cnt.ipa_ca = ipa_fixture

    try:
        for u in cnt.lib_conf["users"]:
            cnt.setup_user(u)
        for p in [t["card_dir"] for t in cnt.lib_conf["users"]]:
            assert p.joinpath("sofhtsm2.conf").exists()
    finally:
        for u in cnt.users:
            u.delete_user()
