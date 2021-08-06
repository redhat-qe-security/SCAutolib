from SCAutolib.src import virt_card, exceptions
from os.path import curdir


def test_run_cmd_simple_cmd():
    shell = virt_card.VirtCard("test-user").run_cmd("pwd")
    assert curdir in str(shell.stdout)
