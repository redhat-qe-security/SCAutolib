import pytest
import pwd
import os
from pathlib import Path

from SCAutolib.models.CA import LocalCA
from SCAutolib.utils import dump_to_json
from SCAutolib.models.user import BaseUser


@pytest.mark.skipif(os.getuid() != 0, reason="Requires root privileges!")
def test_add_and_remove_local_user(local_user):
    local_user.add_user()
    assert pwd.getpwnam(local_user.username)

    local_user.delete_user()
    with pytest.raises(Exception):
        pwd.getpwnam(local_user.username)


def test_add_and_remove_key_cert_pair(local_user):
    cwd = Path(os.getcwd())
    ca = LocalCA(cwd)
    ca.setup()

    local_user.key = ca._ca_key
    local_user.cert = ca._ca_cert
    assert local_user.key == ca._ca_key
    assert local_user.cert == ca._ca_cert

    del local_user.key
    del local_user.cert

    assert local_user.cert is None
    assert local_user.key is None


def test_add_and_remove_cnf(local_user):
    ca = LocalCA(Path(os.getcwd()))
    ca.setup()

    local_user.cnf = ca._ca_cnf
    assert local_user.cnf == ca._ca_cnf

    del local_user.cnf
    assert local_user.cnf is None


def test_dump_and_load_user(local_user):
    dump_to_json(local_user)

    user = BaseUser.load(local_user.dump_file)

    assert user.username == local_user.username
    assert user.pin == local_user.pin
    assert user.password == local_user.password
    assert user.card_dir == local_user.card_dir