from SCAutolib.src.models import ca, local_ca, ipa_server
from pathlib import Path
import pytest


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
