# author: Pavel Yadlouski <pyadlous@redhat.com>
# Unit tests for of SCAutolib.src.env_cli module
import pytest
from click.testing import CliRunner
from SCAutolib.src import env_cli
from SCAutolib.test.fixtures import *
from os.path import basename, exists
from yaml import load, dump, Loader
from subprocess import check_output
import pwd


@pytest.fixture(scope="module")
def runner():
    return CliRunner()


def test_prepare_fail_config(config_file_incorrect, caplog, runner):
    """Test missing value in configuration file would cause non-zero exit code
    of prepare command."""
    result = runner.invoke(env_cli.prepare, ["--conf", config_file_incorrect],
                           catch_exceptions=False, color=True)
    msg = "Field root_passwd is not present in the config."
    assert result.exit_code == 1
    assert msg in caplog.text


def test_cleanup(real_factory, loaded_env, caplog, runner, clean_conf, test_user):
    """Test that cleanup command cleans and resotres necessary
    items."""
    env_path, _ = loaded_env
    load_dotenv(env_path)
    config_file = environ["CONF"]

    src_dir_not_backup = real_factory.create_dir()

    src_dir_parh = real_factory.create_dir()

    dest_dir_path = real_factory.create_dir()
    dest_dir_file = real_factory.create_file(dest_dir_path)
    with open(dest_dir_file, "w") as f:
        f.write("content in src_dir_file")

    src_file_not_bakcup = real_factory.create_file()

    src_file = real_factory.create_file()

    dest_file = real_factory.create_file()
    with open(dest_file, "w") as f:
        f.write("Some content")

    with open(config_file, "r") as f:
        data = load(f, Loader=Loader)

    data["restore"].append({"type": "dir", "src": str(src_dir_parh), "backup_dir": str(dest_dir_path)})
    data["restore"].append({"type": "file", "src": str(src_file), "backup_dir": str(dest_file)})
    data["restore"].append({"type": "dir", "src": str(src_dir_not_backup)})
    data["restore"].append({"type": "file", "src": str(src_file_not_bakcup)})
    data["restore"].append({"type": "user", "username": test_user})
    data["restore"].append({"type": "wrong-type", "src": "no_src"})

    with open(config_file, "w") as f:
        dump(data, f)
    # Run cleanup command
    result = runner.invoke(env_cli.cleanup, catch_exceptions=False, color=True)

    # General sucess of the command
    assert result.exit_code == 0
    assert "Start cleanup" in caplog.messages
    assert "Cleanup is completed" in caplog.messages

    # File is correctly restored
    assert f"File {src_file} is restored form {dest_file}" in caplog.messages
    with open(src_file, "r") as f:
        assert "Some content" in f.read()

    # File is correctly deleted
    assert f"File {src_file_not_bakcup} is deleted" in caplog.messages
    assert not exists(src_file_not_bakcup)

    # Directory is correctly restored
    assert f"Directory {src_dir_parh} is restored form {dest_dir_path}" in caplog.messages
    backuped_file = f"{src_dir_parh}/{basename(dest_dir_file)}"
    assert exists(backuped_file)
    with open(backuped_file, "r") as f:
        assert "content in src_dir_file" in f.read()

    # Directory is correctly deleted
    assert f"Directory {src_dir_not_backup} is deleted"
    assert not exists(src_file_not_bakcup)

    # User is correctly deleted
    assert f"User test-user is delete with it home directory" in caplog.messages
    with pytest.raises(KeyError):
        pwd.getpwnam('test-name')

    # Item with uknown type is skipped
    assert "Skip item with unknow type 'wrong-type'" in caplog.messages
