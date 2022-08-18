from subprocess import check_output, run

import json
from os.path import exists

import pytest
from click.testing import CliRunner
from pwd import getpwnam
from SCAutolib import LIB_DUMP_USERS
from SCAutolib.cli_commands import ReturnCode
from SCAutolib.controller import Controller

import SCAutolib.cli_commands as cli_cmd


@pytest.fixture(scope="module", autouse=True)
def runner():
    return CliRunner()


@pytest.mark.parametrize("username", ["local-user", "not-existing-user"])
@pytest.mark.parametrize("ca", ["local", None])
@pytest.mark.service_restart
def test_cli_setup_user(dummy_config, runner, username, ca, tmpdir):
    """Test the CLI command setup-user."""
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

    # assert LIB_DUMP_USERS.joinpath(f"{username}.json").exists()
