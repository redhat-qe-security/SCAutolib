# author: Pavel Yadlouski <pyadlous@redhat.com>
# Unit tests for of SCAutolib.src.env_cli module
import subprocess
import pytest
from yaml import FullLoader
from click.testing import CliRunner
from SCAutolib.src import env_cli
from SCAutolib.test.fixtures import *
from os.path import basename, exists
from yaml import load, dump, Loader
from subprocess import check_output, run, PIPE
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
    assert msg in caplog.messages


@pytest.mark.slow()
@pytest.mark.service_restart()
def test_prepare_simple_fail_on_packages(config_file_correct, runner, caplog):
    package = "softhsm"
    subprocess.check_output(["dnf", "remove", package, "-y"], encoding="utf-8")
    # Act
    result = runner.invoke(env_cli.prepare, ["--conf", config_file_correct])

    # Assert
    try:
        assert result.exit_code == 1
        assert f"Package {package} is required for testing, but it is not " \
               f"installed on the system." in caplog.messages
        assert "General setup is failed" in caplog.messages
    finally:
        subprocess.check_output(["dnf", "install", package, "-y"],
                                encoding="utf-8")


@pytest.mark.slow()
@pytest.mark.service_restart()
def test_prepare_simple_install_missing(config_file_correct, runner, caplog):
    # Act
    result = runner.invoke(
        env_cli.prepare, ["--conf", config_file_correct, "-m"])

    # Assert
    assert result.exit_code == 0
    assert "General setup is done" in caplog.messages
    msg = "Base user with username 'base-user' is created with no password"
    assert msg in caplog.messages
    assert "Preparation of the environments is completed" in caplog.messages


@pytest.mark.ipa()
def test_prepare_ipa_no_ip(config_file_correct, caplog, runner):
    result = runner.invoke(env_cli.prepare, ["--conf", config_file_correct,
                                             "--ipa"])
    assert result.exit_code == 1
    assert "No IP address for IPA server is given." in caplog.messages
    assert "Can't find IP address of IPA server in configuration file" \
           in caplog.messages


@pytest.mark.ipa()
def test_prepare_ca(config_file_correct, caplog, runner):
    result = runner.invoke(env_cli.prepare, ["--conf", config_file_correct,
                                             "--ca"])
    assert result.exit_code == 0
    assert "Start setup of local CA" in caplog.messages
    assert "Setup of local CA is completed" in caplog.messages


@pytest.mark.slow()
@pytest.mark.service_restart()
def test_prepare_ca_cards(config_file_correct, caplog, runner, src_path):
    result = runner.invoke(
        env_cli.prepare, ["--conf", config_file_correct, "--ca", "--cards"])

    with open(config_file_correct, "r") as f:
        data = load(f, Loader=FullLoader)
        user = data["local_user"]
        username = user["name"]
        card_dir = user["card_dir"]
        conf_dir = join(card_dir, "conf")

    assert result.exit_code == 0
    assert f"Start setup of virtual smart cards for local user {user}" \
           in caplog.messages
    assert exists(join(conf_dir, "softhsm2.conf"))
    service_path = f"/etc/systemd/system/virt_cacard_{username}.service"
    assert exists(service_path)

    with open(service_path, "r") as f:
        content = f.read()

    assert f"virtual card for {username}" in content
    assert f'SOFTHSM2_CONF="{conf_dir}/softhsm2.conf"' in content
    assert f'WorkingDirectory = {card_dir}' in content
    run(['systemctl', 'start', f'virt_cacard_{username}'],
        encoding='utf-8', stderr=PIPE, stdout=PIPE, check=True)


@pytest.mark.slow()
@pytest.mark.service_restart()
@pytest.mark.ipa()
def test_prepare_ipa(config_file_correct, caplog, runner, ipa_ip, ipa_hostname):
    with open("/etc/hosts", "r") as f:
        content = f.read()
    entry = f"{ipa_ip} {ipa_hostname}"
    if entry in content:
        with open("/etc/hosts", "w") as f:
            f.write(content.replace(entry, ""))

    result = runner.invoke(env_cli.prepare,
                           ["--conf", config_file_correct, "--ipa",
                            "--server-ip", ipa_ip, "--server-hostname",
                            ipa_hostname])
    try:
        assert result.exit_code == 0
        with open("/etc/hosts", "r") as f:
            assert f"{ipa_ip} {ipa_hostname}" in f.read()
        with open("/etc/sssd/pki/sssd_auth_ca_db.pem", "r") as f:
            with open("/etc/ipa/ca.crt") as f_cert:
                assert f_cert.read() in f.read()
        assert run(["ipa", "user-find"]).returncode == 0
        assert "Start setup of IPA client" in caplog.messages
        assert f"New entry {ipa_ip} {ipa_hostname} is added to /etc/hosts" \
               in caplog.messages
    finally:
        check_output(["ipa-client-install", "--uninstall", "-U"])


@pytest.mark.slow()
@pytest.mark.service_restart()
@pytest.mark.ipa()
def test_prepare_ipa_cards(config_file_correct, caplog, runner, ipa_ip,
                           ipa_hostname, src_path, ipa_user, ipa_metaclient):
    result = runner.invoke(env_cli.prepare,
                           ["--conf", config_file_correct, "--ipa",
                            "--server-ip", ipa_ip, "--server-hostname",
                            ipa_hostname, "--cards"])

    with open(config_file_correct, "r") as f:
        data = load(f, Loader=FullLoader)

    user = data["ipa_user"]
    username = user['name']
    card_dir = user["card_dir"]
    conf_dir = join(card_dir, "conf")
    try:
        assert result.exit_code == 0
        msg = f"User {username} is updated on IPA server. " \
              f"Cert and key stored into"
        assert msg in caplog.text
        service_path = f"/etc/systemd/system/virt_cacard_{username}.service"
        assert exists(service_path)
        with open(service_path, "r") as f:
            content = f.read()
        assert f"virtual card for {username}" in content

        assert f'SOFTHSM2_CONF="{conf_dir}/softhsm2.conf"' in content
        assert f'WorkingDirectory = {card_dir}' in content
    finally:
        ipa_metaclient.user_del(ipa_user, o_preserve=False)
        check_output(["ipa-client-install", "--uninstall", "-U"])


@pytest.mark.slow()
def test_cleanup(real_factory, loaded_env, caplog, runner, test_user):
    """Test that cleanup command cleans and restores necessary
    items."""
    config_file = loaded_env

    # Start process with specific user
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

    data["restore"] = []
    data["restore"].append({"type": "dir", "src": str(
        src_dir_parh), "backup_dir": str(dest_dir_path)})
    data["restore"].append({"type": "file", "src": str(
        src_file), "backup_dir": str(dest_file)})
    data["restore"].append({"type": "dir", "src": str(src_dir_not_backup)})
    data["restore"].append({"type": "file", "src": str(src_file_not_bakcup)})
    data["restore"].append({"type": "user", "src": test_user})
    data["restore"].append({"type": "wrong-type", "src": "no_src"})

    with open(LIB_CONF, "w") as f:
        dump(data, f)
    # Run cleanup command
    result = runner.invoke(env_cli.cleanup, catch_exceptions=False, color=True)

    # General success of the command
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
    assert f"Directory {src_dir_parh} is restored form {dest_dir_path}" \
           in caplog.messages
    backuped_file = f"{src_dir_parh}/{basename(dest_dir_file)}"
    assert exists(backuped_file)
    with open(backuped_file, "r") as f:
        assert "content in src_dir_file" in f.read()

    # Directory is correctly deleted
    assert f"Directory {src_dir_not_backup} is deleted"
    assert not exists(src_dir_not_backup)

    # User is correctly deleted
    assert f"Local user {test_user['name']} is removed." in caplog.messages
    with pytest.raises(KeyError):
        pwd.getpwnam('test-name')

    # Item with unknown type is skipped
    assert "Skip item with unknown type 'wrong-type'" in caplog.messages


@pytest.mark.service_restart
def test_prepare_gdm_not_required(runner, config_file_correct, caplog):
    result = runner.invoke(env_cli.prepare, ["--conf", config_file_correct,
                                             "--no-gdm"])
    assert result.exit_code == 0
    assert "GDM package is not required on the system." in caplog.messages
