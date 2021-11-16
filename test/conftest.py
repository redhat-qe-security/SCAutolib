import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--ipa-ip", action="store", help="IP address of IPA server", default="")
    parser.addoption(
        "--ipa-hostname", action="store", help="Hostname of IPA server",
        default="")
    parser.addoption("--not-in-ci", action="store_true", default=False,
                     help="Mark test to not run in GitHib CI")


def pytest_generate_tests(metafunc):
    ipa_ip = metafunc.config.option.ipa_ip
    ipa_hostname = metafunc.config.option.ipa_hostname
    if 'ipa_ip' in metafunc.fixturenames and ipa_ip is not None:
        metafunc.parametrize("ipa_ip", [ipa_ip])
    if 'ipa_hostname' in metafunc.fixturenames and ipa_hostname is not None:
        metafunc.parametrize("ipa_hostname", [ipa_hostname])


def pytest_collection_modifyitems(config, items):
    if config.getoption("--not-in-ci"):
        not_in_ci = pytest.mark.skip(
            reason="Test can't be executed in GitHub CI")
        for item in items:
            if "not_in_ci" in item.keywords:
                item.add_marker(not_in_ci)
