import os
import pwd
import pytest
from pathlib import Path
from shutil import copy
from shutil import copyfile
from subprocess import check_output, run, CalledProcessError, PIPE

from SCAutolib.models import CA
from SCAutolib.models.card import VirtualCard
from SCAutolib.models.file import SSSDConf, File, OpensslCnf
from SCAutolib.models.user import User

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(DIR_PATH, "files")


@pytest.fixture()
def dummy_config(tmp_path):
    config_path = f'{tmp_path}/dummy_config_file.json'
    copy(f"{FILES_DIR}/dummy_config_file.json", config_path)
    with open(f"{FILES_DIR}/dummy_config_file.json", "r") as f:
        cnt = f.read()
    with open(config_path, "w") as f:
        f.write(cnt.replace("{path}", str(tmp_path)))

    return config_path


@pytest.fixture(scope="session")
def ipa_fixture(ipa_config):
    client_name = f'client-{ipa_config["hostname"]}'
    cmd = ["ipa-client-install", "-p", "admin",
           "--password", ipa_config["admin_passwd"],
           "--server", ipa_config["hostname"],
           "--domain", ipa_config["domain"],
           "--realm", ipa_config["domain"].upper(),
           "--hostname", client_name,
           "--all-ip-addresses", "--force", "--force-join",
           "--no-ntp", "-U"]

    proc = run(cmd, input="yes", encoding="utf-8", stdout=PIPE, stderr=PIPE)
    # Return code 3 is a return code when IPA client is already installed
    if proc.returncode not in [0, 3]:
        raise CalledProcessError(proc.returncode, cmd)

    return CA.IPAServerCA(ip_addr=ipa_config["ip"],
                          server_hostname=ipa_config["hostname"],
                          admin_passwd=ipa_config["admin_passwd"],
                          root_passwd=ipa_config["root_passwd"],
                          domain=ipa_config["domain"],
                          client_hostname=client_name)


@pytest.fixture(scope="session")
def clean_ipa():
    yield
    run(["ipa-client-install", "--uninstall", "--unattended"],
        encoding="utf-8")


@pytest.fixture(scope="session")
def local_ca_fixture(tmp_path_factory, backup_sssd_ca_db):
    root = tmp_path_factory.mktemp("ca").joinpath("local-ca")
    root.mkdir(exist_ok=True)
    cnf = OpensslCnf(conf_type="CA", filepath=root.joinpath("ca.cnf"),
                     replace=str(root))
    ca = CA.LocalCA(root, cnf)
    try:
        cnf.create()
        cnf.save()
        ca.setup()
    except FileExistsError:
        pass
    return ca


@pytest.fixture
def local_user(tmp_path, request):
    # In linux useradd command max length of the username is 32 chars
    username = f"user-{request.node.name}"[0:32]
    user = User(username, "testpassword", "123456")
    user.card_dir = tmp_path
    user.dump_file = tmp_path.joinpath("test-user-dump-file.json")
    user.card = VirtualCard(user=user)
    yield user

    # Delete the user if it was added during the test phase
    try:
        pwd.getpwnam(username)
        check_output(["userdel", username], encoding="utf-8")
    except KeyError:
        pass


@pytest.fixture()
def file_test_prepare(tmpdir):
    """
    Return instance of File class with custom setup of class variables
    """
    file_test = File(Path(tmpdir, "config"))
    file_test._template = Path(tmpdir, "template")
    return file_test


@pytest.fixture()
def sssd_test_prepare(tmpdir):
    """
    Return instance of SSSDconf class with custom setup of class variables
    """
    sssd_test = SSSDConf()
    sssd_test._conf_file = Path(tmpdir, "config")
    sssd_test._backup_original = Path(tmpdir, "original")
    sssd_test._backup_default = Path(tmpdir, "default")

    return sssd_test


@pytest.fixture(scope="session")
def backup_sssd_ca_db(tmp_path_factory):
    backup = None
    sssd_auth_ca_db = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")
    if sssd_auth_ca_db.exists():
        # Save SSSD CA db
        backup = tmp_path_factory.mktemp("backup").joinpath(
            "sssd_auth_ca_db.pem")
        copyfile(sssd_auth_ca_db, backup)
    yield

    # Restore SSSD CA db
    if backup:
        copyfile(backup, "/etc/sssd/pki/sssd_auth_ca_db.pem")
    else:
        if sssd_auth_ca_db.exists():
            sssd_auth_ca_db.unlink()
