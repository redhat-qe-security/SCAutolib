import pytest
from pathlib import Path
from shutil import copyfile
from subprocess import check_output

from SCAutolib import TEMPLATES_DIR
from SCAutolib.models import CA
from cryptography import x509


@pytest.fixture(scope="session")
def local_ca_fixture(tmp_path_factory, backup_sssd_ca_db):
    ca = CA.LocalCA(tmp_path_factory.mktemp("local-ca"))
    ca.setup(force=True)
    return ca


def test_local_ca_setup(backup_sssd_ca_db, tmpdir, caplog):
    sssd_auth_ca_db = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")
    ca = CA.LocalCA(Path(tmpdir, "ca"))
    ca.setup()

    assert ca.root_dir.exists()
    assert ca._ca_cert.exists()
    assert ca._ca_key.exists()
    assert ca._ca_key.exists()

    with ca._ca_cert.open("r") as f:
        # This directory has to be created by the LocalCA.setup()
        with sssd_auth_ca_db.open()as f_db:
            assert f.read() in f_db.read()

    assert "Local CA is configured" in caplog.messages


@pytest.mark.parametrize("force", (False, True))
def test_local_ca_setup_force(backup_sssd_ca_db, tmpdir, caplog, force):
    ca_dir = Path(tmpdir, "ca")
    tmp_file = ca_dir.joinpath("some-file")
    ca_dir.mkdir()
    tmp_file.touch()

    ca = CA.LocalCA(ca_dir)
    ca.setup(force=force)

    if force:
        assert not tmp_file.exists()
        assert f"Removing local CA {ca_dir}" in caplog.messages
    else:
        assert tmp_file.exists()
        assert "Skipping configuration." in caplog.messages


def test_request_cert(local_ca_fixture, tmpdir):
    csr = Path(tmpdir, "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))

    with cnf.open("r+") as f:
        f.write(f.read().format(user="username"))

    cmd = ['openssl', 'req', '-new', '-days', '365', '-nodes', '-newkey',
           'rsa:2048', '-keyout', f'{tmpdir}/username.key', '-out', csr,
           "-reqexts", "req_exts", "-config", cnf]
    check_output(cmd, encoding="utf-8")

    cert = local_ca_fixture.request_cert(csr, "username")
    assert cert.exists()


def test_revoke_cert(local_ca_fixture, tmpdir):
    csr = Path(tmpdir, "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))
    username = "username1"
    with cnf.open("r+") as f:
        f.write(f.read().format(user=username))
    cmd = ['openssl', 'req', '-new', '-days', '365', '-nodes', '-newkey',
           'rsa:2048', '-keyout', f'{tmpdir}/{username}.key', '-out', csr,
           "-reqexts", "req_exts", "-config", cnf]
    check_output(cmd, encoding="utf-8")

    cert = local_ca_fixture.request_cert(csr, username)
    with cert.open("rb") as f:
        serial_number = x509.load_pem_x509_certificate(f.read()).serial_number

    local_ca_fixture.revoke_cert(cert)

    with open(local_ca_fixture._crl, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())

    revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_number)
    assert revoked_cert is not None
