from fixtures import *  # noqa: F401
from os import environ


def pytest_addoption(parser):
    """
    Define CLI parameters
    """
    parser.addoption(
        "--ipa-ip", action="store", help="IP address of IPA server",
        default=environ["IPA_IP"]
    )
    parser.addoption(
        "--ipa-hostname", action="store", help="Hostname of IPA server",
        default=environ["IPA_HOSTNAME"]
    )
    parser.addoption(
        "--ipa-admin-passwd", action="store",
        default=environ["IPA_ADMIN_PASSWD"],
        help="Admin password for IPA server (for kinit)"
    )
    parser.addoption(
        "--ipa-root-passwd", action="store", default=environ["IPA_ROOT_PASSWD"],
        help="Root password for IPA server (for SSH)"
    )


def pytest_generate_tests(metafunc):
    """
    Inject variables to test. Variables should be specified in test arguments
    """
    ipa_ip = metafunc.config.option.ipa_ip
    ipa_hostname = metafunc.config.option.ipa_hostname
    ipa_admin_passwd = metafunc.config.option.ipa_admin_passwd
    ipa_root_passwd = metafunc.config.option.ipa_root_passwd

    if 'ipa_ip' in metafunc.fixturenames and ipa_ip is not None:
        metafunc.parametrize("ipa_ip", [ipa_ip])
    if 'ipa_hostname' in metafunc.fixturenames and ipa_hostname is not None:
        metafunc.parametrize("ipa_hostname", [ipa_hostname])
    if 'ipa_admin_passwd' in metafunc.fixturenames \
            and ipa_admin_passwd is not None:
        metafunc.parametrize("ipa_admin_passwd", [ipa_admin_passwd])
    if 'ipa_root_passwd' in metafunc.fixturenames \
            and ipa_root_passwd is not None:
        metafunc.parametrize("ipa_root_passwd", [ipa_root_passwd])


def pytest_sessionfinish(session, exitstatus):
    """
    Change behaviour: if no tests found (exit status == 5), for us, it is not a
    fail.
    """
    if exitstatus == 5:
        session.exitstatus = 0
