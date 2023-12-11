import json
import pytest
from click.testing import CliRunner
from pwd import getpwnam
from subprocess import run

import SCAutolib.cli_commands as cli_cmd
from SCAutolib.cli_commands import ReturnCode
from SCAutolib.controller import Controller


@pytest.fixture(scope="module", autouse=True)
def runner():
    return CliRunner()


@pytest.mark.skip(reason="broken test")
@pytest.mark.parametrize("username", ["local-user", "not-existing-user"])
@pytest.mark.parametrize("ca", ["local", None])
@pytest.mark.service_restart
def test_cli_setup_user(dummy_config, runner, username, ca, tmpdir):
    """Test the CLI command setup-user."""
    # FIXME this is rather complex integration test. It's failing and its
    #  difficult to debug it as logging is unexpectedly weak. We should probably
    #  test that cli recognize parameters, however, testing of cli by executing
    #  real commands is arguable.
    if ca == "local":
        Controller(dummy_config).setup_local_ca()
    user_options = []
    if username == "not-existing-user":
        user_options = ["--pin", "123456", "--passwd", "user-passwd",
                        "--card-dir", tmpdir]
    result = runner.invoke(cli_cmd.cli, ["--conf", dummy_config,
                                         "setup-user", username,
                                         *user_options])
    print(result.stdout)
    try:
        if ca == "local":
            if username == "not-existing-user":
                assert f"User {username} not found in config file, trying to " \
                       f"create a new one" in result.output
            assert result.exit_code == ReturnCode.SUCCESS.value
            assert getpwnam(username)
        else:
            assert "CA is not configured on the system" in result.output
    finally:
        run(["userdel", "-r", username], check=False)


@pytest.mark.skip(reason="ipa server not available for tests")
@pytest.mark.ipa
@pytest.mark.parametrize("ca_type", ["all", "local", "ipa"])
def test_setup_ca(runner, dummy_config, ca_type, clean_ipa, ipa_config):
    """Test the CLI command setup-ca."""

    if ca_type in ["all", "ipa"]:
        with open(dummy_config, "r") as f:
            cfg = json.load(f)
        cfg["ca"]["ipa"]["ip_addr"] = ipa_config["ip"]
        cfg["ca"]["ipa"]["server_hostname"] = ipa_config["hostname"]
        cfg["ca"]["ipa"]["admin_passwd"] = ipa_config["admin_passwd"]
        cfg["ca"]["ipa"]["root_passwd"] = ipa_config["root_passwd"]
        cfg["ca"]["ipa"]["domain"] = ipa_config["domain"]
        cfg["ca"]["ipa"]["realm"] = ipa_config["domain"].upper()
        with open(dummy_config, "w") as f:
            json.dump(cfg, f)

    result = runner.invoke(cli_cmd.cli, ["--conf", dummy_config,
                                         "setup-ca", "--ca-type", ca_type])

    print(result.stdout)
    assert result.exit_code == ReturnCode.SUCCESS.value
