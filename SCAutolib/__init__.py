from enum import Enum, auto

import coloredlogs
import logging
import subprocess
from pathlib import Path
import time
from schema import Schema, Use, Or, And, Optional

fmt = "%(name)s:%(module)s.%(funcName)s.%(lineno)d [%(levelname)s] %(message)s"
date_fmt = "%H:%M:%S"
coloredlogs.install(level="DEBUG", fmt=fmt, datefmt=date_fmt,
                    field_styles={'levelname': {'bold': True, 'color': 'blue'}})
logger = logging.getLogger(__name__)
# Disable logs from imported packages
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("invoke").setLevel(logging.WARNING)
logging.getLogger("fabric").setLevel(logging.WARNING)

DIR_PATH = Path(__file__).parent
TEMPLATES_DIR = DIR_PATH.joinpath("templates")

LIB_DIR = Path("/etc/SCAutolib")
SETUP_IPA_SERVER = LIB_DIR.joinpath("ipa-install-server.sh")
LIB_BACKUP = LIB_DIR.joinpath("backup")
LIB_DUMP = LIB_DIR.joinpath("dump")
LIB_DUMP_USERS = LIB_DUMP.joinpath("users")
LIB_DUMP_CAS = LIB_DUMP.joinpath("cas")
LIB_DUMP_CARDS = LIB_DUMP.joinpath("cards")


schema_cas = Schema(And(
    Use(dict),
    # Check that CA section contains at least one and maximum
    # two entries
    lambda l: 1 <= len(l.keys()) <= 2,
    {Optional("local_ca"): {
        Optional("dir", default=Path("/etc/SCAutolib/ca")): Use(Path)},
        Optional("ipa"): {
            'admin_passwd': Use(str),
            'root_passwd': Use(str),
            Optional('ip_addr', default=None): Use(str),
            'server_hostname': Use(str),
            'client_hostname': Use(str),
            'domain': Use(str),
            'realm': Use(str.upper)}}),
    ignore_extra_keys=True)

# Specify validation schema for all users
schema_user = Schema({'name': Use(str),
                      'passwd': Use(str),
                      'pin': Use(str),
                      Optional('card_dir', default=None): Use(Path),
                      'card_type': Or("virtual", "real", "removinator"),
                      Optional('cert', default=None): Use(Path),
                      Optional('key', default=None): Use(Path),
                      'local': Use(bool)})


class ReturnCode(Enum):
    """
    Enum for return codes
    """
    SUCCESS = 0
    MISSING_CA = auto()
    FAILURE = auto()
    ERROR = auto()
    EXCEPTION = auto()
    UNKNOWN = auto()


def run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        print_=True, return_code: list = None, sleep: int = 0, **kwargs) \
        -> subprocess.CompletedProcess:
    """
    Wrapper for subrpocess.run function. This function explicitly set several
    parameter of original function and also provides similar thing as
    subprocess.check_output do. But with having this wrapper, functionality
    of this two functions is generalized and can be changed by setting
    corresponding parameters. If there are any specific parameter of
    subprocess.run function needed to be passed to this wrapper, you can do
    it by adding same parameters names in key=value format.

    :param sleep: time to sleep after command is executed
    :type sleep: int
    :param return_code: acceptable return codes from given commands.
        If check=True, and the return code of the cmd is not in the return_code
        list an subprocess.CalledProcessError exception would be raised.
    :type return_code: list
    :param cmd: Command to be executed
    :type cmd: list or str
    :param stdout: Redirection of stdout. Default is subprocess.PIPE
    :type stdout: None or int or IO
    :param stderr: Redirection of stderr. Default is subprocess.PIPE
    :type stderr: None or int or IO
    :param check: Specifies it return code of the command would be checked for
        0 (if return code == 0). If True and return code is not 0, then
        subprocess.CalledProcessError exception would be risen. Default is
        False.
    :type check: bool
    :param print_: Specifies it stdout and stderr should be printed to the
        terminal. Log message with stdout would have debug type and stderr
        log message would have error type. Default is True.
    :type print_: bool
    :param kwargs: Other parameters to subprocess.run function

    :exception subprocess.CalledProcessError:

    :return: Completed process from subprocess.run
    :rtype: subprocess.CompletedProcess
    """
    if return_code is None:
        return_code = [0]
    if type(cmd) == str:
        cmd = cmd.split(" ")
    logger.debug(f"run: {' '.join([str(i) for i in cmd])}")
    out = subprocess.run(cmd, stdout=stdout, stderr=stderr, encoding="utf-8",
                         **kwargs)
    if print_:
        if out.stdout != "":
            logger.debug(out.stdout)
        if out.stderr != "":
            logger.warning(out.stderr)

    if check:
        if out.returncode not in return_code:
            logger.error(f"Unexpected return code {out.returncode}. "
                         f"Expected: {return_code}")
            raise subprocess.CalledProcessError(out.returncode, cmd)
    time.sleep(sleep)
    return out
