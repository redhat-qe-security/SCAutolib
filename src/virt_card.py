import time
import pexpect
import subprocess as subp
from SCAutolib import log


class VirtCard:
    def __init__(self, insert=False):
        self._inserted = insert
        log.debug("Smart card initialized")

    def __enter__(self):
        if self._inserted:
            self.insert()
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        if exp_type is not None:
            log.error("Exception in authselect context")
            log.error(f"Exception type: {exp_type}")
            log.error(f"Exception value: {exp_value}")
            log.error(f"Exception traceback: {exp_traceback}")
        self.remove()

    def remove(self):
        rc = subp.run(["systemctl", "stop", "virt_cacard.service"])
        time.sleep(2)
        msg = "Smart card removal failed"
        assert rc.returncode == 0, msg
        self._inserted = False
        log.debug("Smart card removed")

    def insert(self):
        rc = subp.run(["systemctl", "start", "virt_cacard.service"])
        time.sleep(2)
        msg = "Smart card insert failed"
        assert rc.returncode == 0, msg
        self._inserted = True
        log.debug("Smart card is inserted")

    def enroll(self):
        log.debug("Smart card enrolled")

    def run_cmd(self, cmd, expect, pin=True, passwd=None, shell=None):
        try:
            if shell is None:
                shell = pexpect.spawn(cmd, encoding='utf-8')
            shell.maxread = 1000
            if passwd is not None:
                pattern = "PIN for " if pin else "Password"
                time.sleep(1)
                out = shell.expect([pexpect.TIMEOUT, pattern], timeout=10)
                if out == 0:
                    log.info("pshell() timed out on passsword / PIN waiting")
                assert out == 1
                shell.sendline(passwd)

            out = shell.expect([pexpect.TIMEOUT, expect], timeout=20)
            if out == 0:
                log.info("\npshell() timed out\n")
            assert out == 1, "Wrong pattern is matched"

        except pexpect.exceptions.EOF as e:
            log.error(
                f"Pattern '{expect}' not found in output.\n"
                f"Output:\n{str(shell.before)}")
            raise e
        except Exception as e:
            log.error(f"Unexpected exception: {str(e)}")
            raise e
        return shell
