from SCAutolib.src.models import ca, local_ca, ipa_server
from pathlib import Path
import pytest
from SCAutolib.test.fixtures import local_ca
from subprocess import check_output
from shutil import copyfile
from SCAutolib.src import TEMPLATES_DIR


def test_local_ca_setup(tmpdir, caplog):
    ca = local_ca.LocalCA(Path(tmpdir, "ca"))
    ca.setup()

    assert ca.root_dir.exists()
    assert ca._ca_cert.exists()
    assert ca._ca_key.exists()
    assert ca._ca_key.exists()

    with ca._ca_cert.open("r") as f:
        # This directory has to be created by the LocalCA.setup()
        with open("/etc/sssd/pki/sssd_auth_ca_db.pem", "r") as f_db:
            assert f.read() in f_db.read()

    assert "Local CA is configured" in caplog.messages


@pytest.mark.parametrize("force", (False, True))
def test_local_ca_setup_force(tmpdir, caplog, force):
    tmp_file = Path(tmpdir, "ca", "some-file")
    tmp_file.parent.mkdir()
    tmp_file.touch()

    assert tmp_file.exists()

    ca = local_ca.LocalCA(Path(tmpdir, "ca"))
    ca.setup(force=force)

    if force:
        assert not tmp_file.exists()
        assert "Removing configuration." in caplog.messages
    else:
        assert tmp_file.exists()
        assert "Skipping configuration." in caplog.messages


def test_request_cert(local_ca, tmpdir):
    csr = Path(tmpdir,  "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))

    with cnf.open("r+") as f:
        f.write(f.read().format(user="username"))

    cmd = ['openssl', 'req', '-new', '-days', '365', '-nodes', '-newkey',
          'rsa:2048', '-keyout', f'{tmpdir}/username.key', '-out', csr,
           "-reqexts", "req_exts", "-config", cnf]
    check_output(cmd, encoding="utf-8")

    cert = local_ca.request_cert(csr, "username")
    assert cert.exists()
