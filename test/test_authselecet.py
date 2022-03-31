# author: Pavel Yadlouski <pyadlous@redhat.com>
# Unit tests for of SCAutolib.authselect module

from subprocess import check_output

from SCAutolib.models.authselect import Authselect


def test_authselect_init():
    auth = Authselect()
    assert not auth._lock_on_removal
    assert not auth._mk_homedir
    assert not auth._required


def test_authselect_set():
    auth = Authselect()
    auth._set()
    out = check_output(["authselect", "current"], encoding="utf-8")
    try:
        assert "with-smartcard" in out
    finally:
        check_output(["authselect", "backup-restore", auth.backup_name],
                     encoding="utf-8")
