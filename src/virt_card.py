import sys
import time
import pexpect
import subprocess as subp
from SCAutolib import log
from SCAutolib.src.exceptions import *


class VirtCard:
    """
    Class that represents virtual smart card in the tests.
    The of the system level, smart card is represnted as a systemd service.
    Starting and stoping this service simulattes insertion and removing the card.

    This class can be used in context manage (with statment).
    """

    def __init__(self, username, insert=False):
        """
        Constructor for virtual smart card.

        Args:
            insert: specify if virtual smart card should be automatically
                    inserted in the context manager
        """
        self._insert = insert
        self.service_name = f"virt_cacard_{username}.service"
        log.debug("Smart card initialized")

    def __enter__(self):
        if self._insert:
            self.insert()
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        if exp_type is not None:
            log.error("Exception in virtual smart card context")
            log.error(f"Exception type: {exp_type}")
            log.error(f"Exception value: {exp_value}")
            log.error(f"Exception traceback: {exp_traceback}")
        self.remove()

    def remove(self):
        """Simulate removing of the smart card by stopping the systemd service."""
        rc = subp.run(["systemctl", "stop", self.service_name])
        time.sleep(2)
        msg = "Smart card removal failed"
        assert rc.returncode == 0, msg
        log.debug("Smart card removed")

    def insert(self):
        """Simulate inserting of the smart card by starting the systemd service."""
        rc = subp.run(["systemctl", "start", self.service_name])

        time.sleep(2)
        msg = "Smart card insert failed"
        assert rc.returncode == 0, msg
        log.debug("Smart card is inserted")

    def enroll(self):
        """Upload new certificates to the virtual smart card. TO BE DONE"""
        pass

    def run_cmd(self, cmd: str = None, expect: str = None, pin: bool = True,
                passwd: str = None, shell=None, zero_rc: bool = True,
                reject: str = None, ):
        """
        Run to create a child from current shell to run cmd. Try to assert
        expect pattern in the output of the cmd. If cmd require, provide
        login wth given PIN or password. Hitting reject pattern during cmd
        execution cause fail.

        Args:
            cmd: shell command to be executed
            expect: pattern to match in the output. Can be empty string ("")
            reject: control pattern - cause failure if matched before pattern
                    expect is matched
            pin: specify if passwd is a smart card PIN or a password for the
                    user. Base on this, corresnpondign pattern would be matched
                    in login output.
            passwd: smart card PIN or user password if login is needed
            shell: shell child where command need to be execute.
            zero_rc: indicates that it is expected from the command to end with
                     non-zero exit code. Otherwise exception NonZeroReturnCode
                     would be raised
        Returns:
            child of current shell with given command
        """
        try:
            if shell is None and cmd is not None:
                shell = pexpect.spawn(cmd, encoding='utf-8')
            shell.logfile = sys.stdout

            if passwd is not None:
                pattern = "PIN for " if pin else "Password"
                out = shell.expect([pexpect.TIMEOUT, pattern], timeout=10)

                if out != 1:
                    if out == 0:
                        log.error("Timed out on passsword / PIN waiting")
                    expect = pattern

                    raise Exception(f"Pattern '{pattern}' is not "
                                    f"found in the output.")
                shell.sendline(passwd)

            if reject is not None:
                out = shell.expect([reject, pexpect.EOF])
                if out == 0:
                    log.error("Disallowed pattern found")
                    # add exception here

            if expect is not None:
                out = shell.expect([pexpect.TIMEOUT, expect], timeout=20)
                if out != 1:
                    raise PatternNotFound(expect, f"Pattern '{expect}' is not "
                                                  f"found in the output.")

            shell.sendline("echo $?")
            out = shell.expect([pexpect.TIMEOUT, "0"])

            if out != 1:
                msg = f"Command {cmd} endede with non zero return code"
                if zero_rc:
                    raise NonZeroReturnCode(cmd, msg)
                else:
                    log.warn(msg)

        except PatternNotFound as e:
            log.error(f"Pattern '{expect}' not found in output.")
            log.error(f"Command: {cmd}")
            log.error(f"Output:\n{str(shell.before)}\n")
            raise e
        except Exception as e:
            raise e
        return shell
