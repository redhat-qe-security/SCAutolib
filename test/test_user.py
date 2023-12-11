import os
import pwd
import pytest

from SCAutolib.models.user import User
from SCAutolib.utils import dump_to_json


@pytest.mark.skipif(os.getuid() != 0, reason="Requires root privileges!")
def test_add_and_remove_local_user(local_user):
    local_user.add_user()
    assert pwd.getpwnam(local_user.username)

    local_user.delete_user()
    with pytest.raises(Exception):
        pwd.getpwnam(local_user.username)


def test_dump_and_load_user(local_user):
    dump_to_json(local_user)

    user = User.load(local_user.dump_file)

    assert user.username == local_user.username
    assert user.password == local_user.password
    assert user.user_type == local_user.user_type
