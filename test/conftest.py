def pytest_addoption(parser):
    parser.addoption("--ipa-ip", action="store", help="IP address of IPA server")
    parser.addoption("--ipa-hostname", action="store", help="Hostname of IPA server")


def pytest_generate_tests(metafunc):
    ipa_ip = metafunc.config.option.ipa_ip
    ipa_hostname = metafunc.config.option.ipa_hostname
    if 'ipa_ip' in metafunc.fixturenames and ipa_ip is not None:
        metafunc.parametrize("ipa_ip", [ipa_ip])
    if 'ipa_hostname' in metafunc.fixturenames and ipa_hostname is not None:
        metafunc.parametrize("ipa_hostname", [ipa_hostname])
