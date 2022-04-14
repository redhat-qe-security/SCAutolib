from fixtures import *  # noqa: F401


def pytest_addoption(parser):
    parser.addoption(
        "--ipa-ip", action="store", help="IP address of IPA server")
    parser.addoption(
        "--ipa-hostname", action="store", help="Hostname of IPA server")
    parser.addoption(
        "--ipa-passwd", action="store", help="Admin password for IPA server",
        default="SECret.123"
    )


def pytest_generate_tests(metafunc):
    ipa_ip = metafunc.config.option.ipa_ip
    ipa_hostname = metafunc.config.option.ipa_hostname
    ipa_passwd = metafunc.config.option.ipa_passwd
    if 'ipa_ip' in metafunc.fixturenames and ipa_ip is not None:
        metafunc.parametrize("ipa_ip", [ipa_ip])
    if 'ipa_hostname' in metafunc.fixturenames and ipa_hostname is not None:
        metafunc.parametrize("ipa_hostname", [ipa_hostname])
    if 'ipa_passwd' in metafunc.fixturenames and ipa_passwd is not None:
        metafunc.parametrize("ipa_passwd", [ipa_passwd])


def pytest_sessionfinish(session, exitstatus):
    if exitstatus == 5:
        session.exitstatus = 0
