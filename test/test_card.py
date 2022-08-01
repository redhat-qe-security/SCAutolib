import pytest
from pathlib import Path
from subprocess import check_output, run
from time import sleep

from SCAutolib.models.CA import LocalCA
from SCAutolib.models.file import SoftHSM2Conf


@pytest.fixture()
def gen_key_and_cert(local_ca_fixture, local_user):
    csr = Path(local_user.card_dir, f"{local_user.username}.csr")
    cert = Path(local_user.card_dir, f"{local_user.username}.cert")
    key = Path(local_user.card_dir, f"{local_user.username}.key")
    cmd = ["openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048",
           "-keyout", key, "-out", csr, "-subj", f"/CN={local_user.username}"]
    check_output(cmd, encoding="utf-8")

    local_ca_fixture.request_cert(csr, username=local_user.username, cert_out=cert)
    return key, cert


@pytest.fixture()
def local_user_with_smart_card(local_user, gen_key_and_cert):
    hsm_conf = SoftHSM2Conf(Path(local_user.card_dir, "softhsm2.conf"),
                            local_user.card_dir)
    hsm_conf.create()
    hsm_conf.save()

    local_user.key, local_user.cert = gen_key_and_cert
    local_user.card.softhsm2_conf = hsm_conf.path
    yield local_user

    if local_user.card.service_location and \
            local_user.card.service_location.exists():
        local_user.card.service_location.unlink()


@pytest.mark.service_restart
def test_create_and_enroll(local_user_with_smart_card):
    sc = local_user_with_smart_card.card
    user = local_user_with_smart_card
    sc.create()

    sc.enroll()

    assert sc.uri, "Smart card URI is not set"

    # Test phase
    check_output(["systemctl", "start", sc._service_name], encoding="utf-8")
    sleep(3)
    try:
        out = check_output(["pkcs11-tool", "-O", "-l", "-p", f"{user.pin}"],
                           encoding="utf-8")
        for pattern in ["Private Key Object; RSA",
                        "Certificate Object; type = X.509 cert"]:
            assert pattern in out, "Probably some object is not correctly " \
                                   "uploaded to the virtual card"
    finally:
        # Cleanup makes sense only if the service is successfully started
        check_output(["systemctl", "stop", sc._service_name], encoding="utf-8")


@pytest.mark.service_restart
def test_context_manager(local_user_with_smart_card):
    sc = local_user_with_smart_card.card
    sc.create()
    sc.enroll()

    with sc as sc:
        sc.insert()
        out = check_output(["pkcs11-tool", "-O", "-l", "-p",
                            f"{local_user_with_smart_card.pin}"],
                           encoding="utf-8")
        for pattern in ["Private Key Object; RSA",
                        "Certificate Object; type = X.509 cert"]:
            assert pattern in out, "Probably some object is not correctly " \
                                   "uploaded to the virtual card"
    proc = run(["systemctl", "status", sc._service_name])
    assert proc.returncode == 3  # Service is not active
