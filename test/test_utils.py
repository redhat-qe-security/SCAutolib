from shutil import copy

from SCAutolib import utils, LIB_DUMP_USERS
from SCAutolib.models.user import User


def test_load_user(local_user, tmp_path):
    utils.dump_to_json(local_user)
    copy(local_user.dump_file, LIB_DUMP_USERS.joinpath(
        f"{local_user.username}.json"))

    user = User.load(username=local_user.username)
    assert user
