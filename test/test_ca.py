import pytest
import python_freeipa
from cryptography import x509
from pathlib import Path
from python_freeipa.client_meta import ClientMeta
from random import randint
from shutil import copyfile
from subprocess import check_output

from SCAutolib import TEMPLATES_DIR
from SCAutolib.models import CA


@pytest.fixture(scope="session")
def local_ca_fixture(tmp_path_factory, backup_sssd_ca_db):
    ca = CA.LocalCA(tmp_path_factory.mktemp("local-ca"))
    ca.setup(force=True)
    return ca


@pytest.fixture()
def dummy_ipa_vals(ipa_ip, ipa_hostname, ipa_admin_passwd, ipa_root_passwd):
    """
    Creates dummy values for IPA serve and client for testings
    """
    domain = ipa_hostname.split(".", 1)[1]
    return {
        "server_ip": ipa_ip,
        "server_domain": domain,
        "server_hostname": ipa_hostname,
        "server_admin_passwd": ipa_admin_passwd,
        "server_realm": domain.upper(),
        "server_root_passwd": ipa_root_passwd,
        "client_hostname": f"client-hostname.{domain}"
    }


@pytest.fixture()
def dummy_user():
    class User:
        def __init__(self):
            self.username = f"username-{randint(1, 100)}"
            self.password = f"password-{self.username}"

    return User()


@pytest.fixture()
def ipa_meta_client(dummy_ipa_vals):
    """
    Return ready-to-use IPA MetaClient with admin login. This fixture might not
    work if there is no mapping rule on your system for given IPA IP address and
    IPA hostnames (no corresponding entry in /etc/hosts)
    """
    client = ClientMeta(dummy_ipa_vals["server_hostname"], verify_ssl=False)
    client.login("admin", dummy_ipa_vals["server_admin_passwd"])
    return client


@pytest.fixture()
def installed_ipa(dummy_ipa_vals, clean_ipa):
    check_output(["ipa-client-install", "-p", "admin",
                  "--password", dummy_ipa_vals["server_admin_passwd"],
                  "--server", dummy_ipa_vals["server_hostname"],
                  "--domain", dummy_ipa_vals["server_domain"],
                  "--realm", dummy_ipa_vals["server_realm"],
                  "--hostname", dummy_ipa_vals["client_hostname"],
                  "--all-ip-addresses", "--force", "--force-join",
                  "--no-ntp", "-U"],
                 input="yes", encoding="utf-8")


@pytest.fixture()
def clean_ipa():
    yield
    check_output(["ipa-client-install", "--uninstall", "--unattended"],
                 encoding="utf-8")


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
        with sssd_auth_ca_db.open() as f_db:
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


@pytest.mark.ipa
@pytest.mark.parametrize("force", (False, True))
def test_ipa_server_setup_force(installed_ipa, force, dummy_ipa_vals,
                                ipa_meta_client, caplog):
    ipa_ca = CA.IPAServerCA(ip_addr=dummy_ipa_vals["server_ip"],
                            client_hostname=dummy_ipa_vals[
                                "client_hostname"],
                            server_hostname=dummy_ipa_vals["server_hostname"],
                            root_passwd=dummy_ipa_vals[
                                "server_root_passwd"],
                            admin_passwd=dummy_ipa_vals[
                                "server_admin_passwd"],
                            domain=dummy_ipa_vals["server_domain"])
    ipa_ca.setup(force)

    # Test if meta client can get info about freshly configured host
    ipa_meta_client.host_show(a_fqdn=dummy_ipa_vals["client_hostname"])

    # Cleanup after test
    ipa_meta_client.host_del(a_fqdn=dummy_ipa_vals["client_hostname"])

    msg = "IPA client is already configured on this system."
    assert msg in caplog.messages
    if not force:
        msg = "Set force argument to True if you want to remove " \
              "previous installation."
        assert msg in caplog.messages


@pytest.mark.ipa
def test_ipa_setup_change_pwpolicy(ipa_meta_client, dummy_ipa_vals, clean_ipa):
    ipa_ca = CA.IPAServerCA(ip_addr=dummy_ipa_vals["server_ip"],
                            client_hostname=dummy_ipa_vals[
                                "client_hostname"],
                            server_hostname=dummy_ipa_vals["server_hostname"],
                            root_passwd=dummy_ipa_vals[
                                "server_root_passwd"],
                            admin_passwd=dummy_ipa_vals[
                                "server_admin_passwd"],
                            domain=dummy_ipa_vals["server_domain"])
    ipa_ca.setup()

    try:
        policy = ipa_meta_client.pwpolicy_show(a_cn="global_policy")["result"]
        assert "0" in policy["krbminpwdlife"]
        assert "365" in policy["krbmaxpwdlife"]
    finally:
        ipa_meta_client.pwpolicy_mod(a_cn="global_policy", o_krbminpwdlife=10,
                                     o_krbmaxpwdlife=300)


@pytest.mark.ipa
def test_ipa_cert_request_and_revoke(installed_ipa, ipa_meta_client,
                                     dummy_ipa_vals, tmpdir, dummy_user):
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

        ipa_ca = CA.IPAServerCA(ip_addr=dummy_ipa_vals["server_ip"],
                                client_hostname=dummy_ipa_vals[
                                    "client_hostname"],
                                server_hostname=dummy_ipa_vals["server_hostname"],
                                root_passwd=dummy_ipa_vals[
                                    "server_root_passwd"],
                                admin_passwd=dummy_ipa_vals[
                                    "server_admin_passwd"],
                                domain=dummy_ipa_vals["server_domain"])
        ipa_ca.setup()
        out = ipa_ca.request_cert(csr, dummy_user.username, cert)

        assert out.suffix == ".pem"
        with out.open("rb") as f:
            cert_obj = x509.load_pem_x509_certificate(f.read())

        # If cert is not properly created, this would raise an IPA exception
        ipa_meta_client.cert_show(a_serial_number=cert_obj.serial_number)

        ipa_ca.revoke_cert(out)
        revoked = ipa_meta_client.cert_show(
            a_serial_number=cert_obj.serial_number)["result"]["revoked"]
        assert revoked
    finally:
        ipa_meta_client.user_del(dummy_user.username)


@pytest.mark.ipa
def test_ipa_user_add(installed_ipa, ipa_meta_client, dummy_ipa_vals,
                      dummy_user):
    try:
        ipa_ca = CA.IPAServerCA(ip_addr=dummy_ipa_vals["server_ip"],
                                client_hostname=dummy_ipa_vals[
                                    "client_hostname"],
                                server_hostname=dummy_ipa_vals["server_hostname"],
                                root_passwd=dummy_ipa_vals[
                                    "server_root_passwd"],
                                admin_passwd=dummy_ipa_vals[
                                    "server_admin_passwd"],
                                domain=dummy_ipa_vals["server_domain"])
        ipa_ca.setup()
        ipa_ca.add_user(dummy_user)

        # If the user is not properly created, this would raise an IPA exception
        ipa_meta_client.user_show(a_uid=dummy_user.username)
    finally:
        ipa_meta_client.user_del(a_uid=dummy_user.username)


@pytest.mark.ipa
def test_ipa_user_del(installed_ipa, ipa_meta_client, dummy_ipa_vals,
                      dummy_user):
    ipa_meta_client.user_add(dummy_user.username, dummy_user.username,
                             dummy_user.username, dummy_user.username,
                             o_userpassword=dummy_user.password)
    ipa_ca = CA.IPAServerCA(ip_addr=dummy_ipa_vals["server_ip"],
                            client_hostname=dummy_ipa_vals[
                                "client_hostname"],
                            server_hostname=dummy_ipa_vals["server_hostname"],
                            root_passwd=dummy_ipa_vals[
                                "server_root_passwd"],
                            admin_passwd=dummy_ipa_vals[
                                "server_admin_passwd"],
                            domain=dummy_ipa_vals["server_domain"])
    ipa_ca.setup()
    ipa_ca.del_user(dummy_user)

    # If the user is not properly created, this would raise an IPA exception
    with pytest.raises(python_freeipa.exceptions.NotFound):
        ipa_meta_client.user_show(a_uid=dummy_user.username)
