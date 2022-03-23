from SCAutolib.src.models import ca, local_ca, ipa_server
from pathlib import Path
from SCAutolib.src.models.ipa_server import IPAServerCA
import pytest
from SCAutolib.test.fixtures import local_ca_fixture, ipa_ca_fixture, remove_ipa_client
from subprocess import check_output
from shutil import copyfile
from SCAutolib.src import TEMPLATES_DIR
import re


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


def test_request_cert(local_ca_fixture, tmpdir):
    csr = Path(tmpdir,  "username.csr")
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
    csr = Path(tmpdir,  "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))
    username = "username"
    with cnf.open("r+") as f:
        f.write(f.read().format(user=username))
    cmd = ['openssl', 'req', '-new', '-days', '365', '-nodes', '-newkey',
          'rsa:2048', '-keyout', f'{tmpdir}/{username}.key', '-out', csr,
           "-reqexts", "req_exts", "-config", cnf]
    check_output(cmd, encoding="utf-8")

    cert = local_ca_fixture.request_cert(csr, username)
    local_ca_fixture.revoke_cert(cert)

    with local_ca_fixture._serial.open("r") as f:
        index = int(f.read()) - 1

    rex = re.compile(
        f"^R\s+[0-9A-Z]+\s+[0-9A-Z]+\s+.*{index}\s+.*\/CN={username}\n$")

    with open(Path(local_ca_fixture.root_dir, "index.txt"), "r") as f:
        assert re.match(rex, f.read())


def test_ipa_server_ca_setup(ipa_ip, ipa_hostname, remove_ipa_client):
    ipa_client = IPAServerCA(ip_addr=ipa_ip, hostname=ipa_hostname,
                             domain="sc.test.com", admin_passwd="SECret.123",
                             root_passwd="redhat",
                             client_hostname="client.sc.test.com")
    ipa_client.setup()

    with open("/etc/ipa/ca.crt") as f:
        with open("/etc/sssd/pki/sssd_auth_ca_db.pem") as f_db:
            assert f.read() in f_db.read()


@pytest.mark.parametrize("force", (False, True))
def test_ipa_server_setup_force(ipa_ip, ipa_hostname, remove_ipa_client,
                                force, caplog, ipa_ca_fixture):
    ipa_client = IPAServerCA(ip_addr=ipa_ip, hostname=ipa_hostname,
                             domain="sc.test.com", admin_passwd="SECret.123",
                             root_passwd="redhat",
                             client_hostname="client.sc.test.com")
    ipa_client.setup(force=force)
    if force:
        assert "System is configured on some IPA server." in caplog.messages
        assert "Previous installation of IPA client is removed." in caplog.messages
    else:
        assert "IPA client is already configured on the system." in caplog.messages

    with open("/etc/ipa/ca.crt") as f:
        with open("/etc/sssd/pki/sssd_auth_ca_db.pem") as f_db:
            assert f.read() in f_db.read()
