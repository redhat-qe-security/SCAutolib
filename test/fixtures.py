import pytest
from pathlib import Path
from shutil import copyfile

from SCAutolib.models.file import SSSDConf, File


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
        sssd_auth_ca_db.unlink()
