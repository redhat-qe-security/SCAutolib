import pytest
from configparser import ConfigParser
from shutil import copy
from subprocess import check_output

from SCAutolib.controller import Controller
from SCAutolib.models.CA import IPAServerCA
from conftest import FILES_DIR


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
def controller(dummy_config):
    return Controller(dummy_config)


@pytest.fixture()
def ready_ipa(ipa_config):
    domain = ipa_config["hostname"].split(".", 1)[1]
    client_name = f'client-{ipa_config["hostname"]}'
    # cmd = ["ipa-client-install", "-p", "admin",
    #      "--password", ipa_config["admin_passwd"],
    #      "--server", ipa_config["hostname"],
    #      "--domain", domain,  # noqa: E501 user everything after first dot as domain, e.g ipa.test.local -> test.local would be used
    #      "--realm", domain.upper(),
    #      "--hostname", client_name,
    #      "--all-ip-addresses", "--force", "--force-join", "--no-ntp", "-U"]
    # check_output(cmd, input="yes", encoding="utf-8")
    return IPAServerCA(ip_addr=ipa_config["ip"],
                       server_hostname=ipa_config["hostname"],
                       admin_passwd=ipa_config["admin_passwd"],
                       root_passwd=ipa_config["root_passwd"],
                       domain=domain,
                       client_hostname=client_name)


def test_parse_config(dummy_config):
    """Test that configuration is parsed and validated properly."""
    cnt = Controller(dummy_config)

    assert cnt.conf_path.is_absolute()
    assert isinstance(cnt.lib_conf, dict)

#
# def test_prepare(controller):
#     """Test for overall setup including dumps."""
#     cnt: Controller = controller
#     cnt.prepare(False, False, False)


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


def test_users_create(controller, tmp_path, ready_ipa):
    """Test for adding local and IPA users to the systems and initializing all
    required files."""
    cnt: Controller = controller
    cnt.ipa_ca = ready_ipa
    for u in cnt.lib_conf["users"]:
        cnt.setup_user(u)

    for p in [t["card_dir"] for t in cnt.lib_conf["users"]]:
        assert p.joinpath("sofhtsm2.conf").exists()


# def test_cas_create(controller):
#     cnt: Controller = controller
#
#
# def test_enroll_card(controller):
#     cnt: Controller = controller
#
#
# def test_cleanup(controller):
#     cnt: Controller = controller
