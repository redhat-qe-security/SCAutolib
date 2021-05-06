# author: Pavel Yadlouski
# Unit tests for of SCAutolib

import pytest
from SCAutolib.src.authselect import Authselect
import subprocess as sub

def test_set():
    auth = Authselect(path_="/root")
    assert not auth._lock_on_removal
    assert not auth._mk_homedir
    assert not auth._required
    rc = auth._set()
    assert rc == 0, "authselect Set is failed"
    out = sub.run(["authselect", "current"], stdout=sub.PIPE)
    print(out.stdout.decode('utf-8'))
