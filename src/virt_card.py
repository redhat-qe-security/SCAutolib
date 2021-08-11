import sys
import time
import pexpect
from subprocess import check_output, PIPE
from SCAutolib import log
from SCAutolib.src.exceptions import *
from traceback import format_exc


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
            log.error(format_exc())
        self.remove()

    def remove(self):
        """Simulate removing of the smart card by stopping the systemd service."""
        check_output(["systemctl", "stop", self.service_name], stderr=PIPE, encoding='utf-8')
        time.sleep(2)
        log.debug("Smart card removed")

    def insert(self):
        """Simulate inserting of the smart card by starting the systemd service."""
        check_output(["systemctl", "start", self.service_name], stderr=PIPE, encoding='utf-8')
        time.sleep(2)
        log.debug("Smart card is inserted")

    def enroll(self):
        """Upload new certificates to the virtual smart card. TO BE DONE"""
        pass

    def run_cmd(self, cmd: str = None, pin: bool = True,
                passwd: str = None, shell=None):
        """
        Run to create a child from current shell to run cmd. Try to assert
        expect pattern in the output of the cmd. If cmd require, provide
        login wth given PIN or password. Hitting reject pattern during cmd
        execution cause fail.

        Args:
            cmd: shell command to be executed
            pin: specify if passwd is a smart card PIN or a password for the
                 user. Base on this, corresnpondign pattern would be matched
                 in login output.
            passwd: smart card PIN or user password if login is needed
            shell: shell child where command need to be execute.
        Returns:
            stdout of executed command (cmd; see above)
        """
        try:
            if shell is None and cmd is not None:
                shell = pexpect.spawn("/bin/bash", ["-c", cmd + ' ; echo "RC:$?"'],
                                      encoding='utf-8')
            shell.logfile = sys.stdout

            if passwd is not None:
                pattern = "PIN for " if pin else "Password"
                out = shell.expect([pexpect.TIMEOUT, pattern], timeout=10)

                if out != 1:
                    if out == 0:
                        log.error("Timed out on passsword / PIN waiting")
                    expect = pattern

                    raise PatternNotFound(f"Pattern '{pattern}' is not "
                                          f"found in the output.")
                shell.sendline(passwd)

        except PatternNotFound:
            log.error(f"Command: {cmd}")
            log.error(f"Output:\n{str(shell.before)}\n")
            raise
        return shell.read()

    def check_output(self, output, expect: list = [], reject: list = [],
                     zero_rc: bool = True, check_rc: bool = False):
        """
        Check "output" for presence of expected and unexpected patterns.

        Check for presence of expected (required) and unexpected (disallowed)
        patterns in the text and raise exceptions if required pattern is missing
        or if any of disallowed patterns is present. Check also presence of
        pattern "RC:[0-9]+" that in current implementation of run_cmd represents
        exit value of executed command and raise an exception in case of
        non-zero value.

        Args:
            expect: list of patterns to be matched in the output
            reject: list of patterns that cause failure if matched in the output
            check_rc: indicates that presence of pattern "RC:0" would be checked
                      and an exception would be raised if the pattern is missing
            zero_rc: indicates that pattern "RC:[1-9]+" should be present
                     instead of "RC:0" and exception would not be raised
        """

        # TODO: add switch and functionality
        #  to check patterns in specified order

        for pattern in reject:
            if pattern in output:
                raise DisallowedPatternFound(f"Disallowed pattern '{pattern}' "
                                             f"was found in the output")

        for pattern in expect:
            if pattern not in output:
                log.error(f"Pattern: {pattern} not found in output")
                log.error(f"Output:\n{output}\n")
                raise PatternNotFound(f"Pattern '{expect}' is not "
                                      f"found in the output.")

        if check_rc:
            if "RC:0" not in output:
                msg = f"Non zero return code indicated"
                if zero_rc:
                    raise NonZeroReturnCode(cmd, msg)
                else:
                    log.warn(msg)

