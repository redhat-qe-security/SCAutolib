def pytest_addoption(parser):
    parser.addoption(
        "--ipa-ip", action="store", help="IP address of IPA server")
    parser.addoption(
        "--ipa-hostname", action="store", help="Hostname of IPA server")


def pytest_generate_tests(metafunc):
    ipa_ip = metafunc.config.option.ipa_ip
    ipa_hostname = metafunc.config.option.ipa_hostname
    if 'ipa_ip' in metafunc.fixturenames:
        if ipa_ip is None:
            ipa_ip = ""
        metafunc.parametrize("ipa_ip", [ipa_ip])
    if 'ipa_hostname' in metafunc.fixturenames:
        if ipa_hostname is None:
            ipa_hostname = ""
        metafunc.parametrize("ipa_hostname", [ipa_hostname])
