import pytest
import python_freeipa
from cryptography import x509
from pathlib import Path
from python_freeipa.client_meta import ClientMeta
from random import randint
from shutil import copyfile
from subprocess import check_output

import SCAutolib.exceptions
from SCAutolib import TEMPLATES_DIR
from SCAutolib.models import CA
from SCAutolib.models.file import OpensslCnf


@pytest.fixture()
def dummy_user():
    class User:
        def __init__(self):
            self.username = f"username-{randint(1, 100)}"
            self.password = f"password-{self.username}"

    return User()


@pytest.fixture()
def ipa_meta_client(ipa_config):
    """
    Return ready-to-use IPA MetaClient with admin login. This fixture might not
    work if there is no mapping rule on your system for given IPA IP address and
    IPA hostnames (no corresponding entry in /etc/hosts)
    """
    client = ClientMeta(ipa_config["hostname"], verify_ssl=False)
    client.login("admin", ipa_config["admin_passwd"])
    return client


def test_local_ca_setup(backup_sssd_ca_db, tmpdir, caplog):
    sssd_auth_ca_db = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")
    root = Path(tmpdir, "ca")
    root.mkdir()
    cnf = OpensslCnf(conf_type="CA", filepath=root.joinpath("ca.cnf"),
                     replace=str(root))
    cnf.create()
    cnf.save()
    ca = CA.LocalCA(root, cnf)
    ca.setup()
    ca.update_ca_db()

    assert ca.root_dir.exists()
    assert ca._ca_cert.exists()
    assert ca._ca_key.exists()

    with ca._ca_cert.open("r") as f:
        # This directory has to be created by the LocalCA.setup()
        with sssd_auth_ca_db.open() as f_db:
            assert f.read() in f_db.read()

    assert "Local CA is updated" in caplog.messages


def test_local_ca_raise_no_cnf(backup_sssd_ca_db, tmpdir, caplog):
    root = Path(tmpdir, "ca")
    root.mkdir()
    cnf = OpensslCnf(conf_type="CA", filepath=root.joinpath("ca.cnf"),
                     replace=str(root))
    ca = CA.LocalCA(root)
    with pytest.raises(SCAutolib.exceptions.SCAutolibException):
        ca.setup()

    cnf.create()
    cnf.save()

    ca.cnf = cnf
    ca.setup()


def test_request_cert(local_ca_fixture, tmpdir):
    csr = Path(tmpdir, "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))

    with cnf.open("r") as f:
        content = f.read()
    content = content.replace('user', 'username')
    content = content.replace('cn', 'username')
    with cnf.open('w') as f:
        f.write(content)

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
    with cnf.open("r") as f:
        content = f.read()
    content = content.replace('user', username)
    content = content.replace('cn', username)
    with cnf.open('w') as f:
        f.write(content)
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


@pytest.mark.skip(reason="ipa server not available for tests")
@pytest.mark.ipa
def test_ipa_server_setup(ipa_config, ipa_meta_client, caplog):
    client_name = f'client-{ipa_config["hostname"]}'
    ipa_ca = CA.IPAServerCA(ip_addr=ipa_config["ip"],
                            server_hostname=ipa_config["hostname"],
                            admin_passwd=ipa_config["admin_passwd"],
                            root_passwd=ipa_config["root_passwd"],
                            domain=ipa_config["domain"],
                            client_hostname=client_name)
    ipa_ca.setup()

    # Test if meta client can get info about freshly configured host
    ipa_meta_client.host_show(a_fqdn=client_name)

    try:
        policy = ipa_meta_client.pwpolicy_show(a_cn="global_policy")["result"]
        assert "0" in policy["krbminpwdlife"]
        assert "365" in policy["krbmaxpwdlife"]
    finally:
        ipa_meta_client.pwpolicy_mod(a_cn="global_policy", o_krbminpwdlife=10,
                                     o_krbmaxpwdlife=300)


@pytest.mark.skip(reason="ipa server not available for tests")
@pytest.mark.ipa
def test_ipa_cert_request_and_revoke(ipa_fixture, ipa_meta_client,
                                     tmpdir, dummy_user):
    csr = Path(tmpdir, "cert.csr")
    key = Path(tmpdir, "cert.key")
    cert = Path(tmpdir, "cert.out")

    cmd = ["openssl", "req", "-new", "-days", "365", "-nodes", "-newkey",
           "rsa:2048", "-keyout", key, "-out", csr, "-subj",
           f"/CN={dummy_user.username}"]
    check_output(cmd, encoding="utf-8")
    try:
        ipa_meta_client.user_add(dummy_user.username, dummy_user.username,
                                 dummy_user.username, dummy_user.username,
                                 o_userpassword=dummy_user.password)

        out = ipa_fixture.request_cert(csr, dummy_user.username, cert)

        assert out.suffix == ".pem"
        with out.open("rb") as f:
            cert_obj = x509.load_pem_x509_certificate(f.read())

        # If cert is not properly created, this would raise an IPA exception
        ipa_meta_client.cert_show(a_serial_number=cert_obj.serial_number)

        ipa_fixture.revoke_cert(out)
        revoked = ipa_meta_client.cert_show(
            a_serial_number=cert_obj.serial_number)["result"]["revoked"]
        assert revoked
    finally:
        ipa_meta_client.user_del(dummy_user.username)


@pytest.mark.skip(reason="ipa server not available for tests")
@pytest.mark.ipa
def test_ipa_user_add(ipa_fixture, ipa_meta_client, dummy_user):
    try:
        ipa_fixture.add_user(dummy_user)

        # If the user is not properly created, this would raise an IPA exception
        ipa_meta_client.user_show(a_uid=dummy_user.username)
    finally:
        ipa_meta_client.user_del(a_uid=dummy_user.username)


@pytest.mark.skip(reason="ipa server not available for tests")
@pytest.mark.ipa
def test_ipa_user_del(ipa_fixture, ipa_meta_client, dummy_user):
    ipa_meta_client.user_add(dummy_user.username, dummy_user.username,
                             dummy_user.username, dummy_user.username,
                             o_userpassword=dummy_user.password)
    ipa_fixture.del_user(dummy_user)

    # If the user is not properly created, this would raise an IPA exception
    with pytest.raises(python_freeipa.exceptions.NotFound):
        ipa_meta_client.user_show(a_uid=dummy_user.username)
