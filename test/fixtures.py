import pytest
from pathlib import Path
from shutil import copyfile

from SCAutolib.models import CA
from SCAutolib.models.card import VirtualCard
from SCAutolib.models.file import SSSDConf, File, OpensslCnf
from SCAutolib.models.user import User


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
    user = User(f"user-{request.node.name}", "testpassword", "123456")
    user.card_dir = tmp_path
    user.dump_file = tmp_path.joinpath("test-user-dump-file.json")
    user.card = VirtualCard(user=user)
    return user


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
