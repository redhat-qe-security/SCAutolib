import subprocess as subp
import pexpect
import logging
import time

log = logging.getLogger("base")


class Authselect:

    backup_name = "tmp.backup"

    def set(self, required=False, lock_on_removal=False, mk_homedir=False):
        args = ["authselect", "select", "sssd", "--backup", self.backup_name,
                "with-smartcard"]

        if required:
            args.append("with-smartcard-required")
        if lock_on_removal:
            args.append("with-smartcard-lock-on-removal")
        if mk_homedir:
            args.append("with-mkhomedir")
        args.append("--force")

        rc = subp.run(args,  stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect command failed. Return code: {rc.returncode}"
        assert rc.returncode == 0, msg
        log.debug(f"SSSD is set to: {' '.join(args)}")
        log.debug(f"Backupfile: {self.backup_name}")

    def reset(self):
        rc = subp.run(["authselect", "backup-restore", self.backup_name,
                       "--debug"], stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect backup-restore failed. Output: {rc.returncode}"
        assert rc.returncode == 0, msg

        rc = subp.run(["authselect", "backup-remove", self.backup_name,
                       "--debug"], stdout=subp.DEVNULL, stderr=subp.STDOUT)
        msg = f"Authselect backup-remove failed. Output: {rc.returncode}"
        assert rc.returncode == 0, msg

        log.debug("Authselect backup file is restored")

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.reset()


class VirtCard:
    def __init__(self):
        log.debug("Smart card initialized")

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.remove()

    def remove(self):
        subp.run(["systemctl", "stop", "virt_cacard.service"])
        log.debug("Smart card removed")

    def insert(self):
        subp.run(["systemctl", "start", "virt_cacard.service"])
        time.sleep(2)
        log.debug("Smart card inserted")

    def enroll(self):
        log.debug("Smart card enrolled")

    def run_cmd(self, cmd, expect, pin=True, passwd=None, shell=None):
        if shell is None:
            shell = pexpect.spawn(cmd)

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

        return shell

    # TODO: create decorator for reseting sssd config and removing the card


class RemCard:
    pass
