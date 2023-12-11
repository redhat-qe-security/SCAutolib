import pytest
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

    cnt.setup_system(install_missing=True, gdm=False, graphical=False)

    for p in packages:
        out = check_output(["rpm", "-qa", p], encoding="utf-8")
        assert p in out
