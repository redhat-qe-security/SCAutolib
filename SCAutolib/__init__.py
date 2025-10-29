"""
This module serves as the initialization point for the SCAutolib package.

It sets up the package-wide logging configuration using ``coloredlogs``.
It defines global constants for directory paths used throughout the library for
templates, backup files, and data dumps.

Additionally, it establishes validation schemas using the ``schema`` library
for various configuration sections, including CAs (Certificate Authorities),
users, and smart cards. These schemas ensure that input data conforms to
expected structures and types, facilitating robust data handling across
SCAutolib's components.

The module also provides a generalized ``run`` function, acting as a wrapper
for ``subprocess.run``. This wrapper standardizes command execution,
logging, error checking, and offers options for controlling standard
output/error, return code validation, and post-execution delays.
"""


import coloredlogs
import logging
import subprocess
from pathlib import Path
import time
from schema import Schema, Use, Or, And, Optional

from SCAutolib.enums import CardType, UserType
from SCAutolib.exceptions import SCAutolibCommandFailed

fmt = ("%(asctime)s %(name)s:%(module)s.%(funcName)s.%(lineno)d "
       "[%(levelname)s] %(message)s")
date_fmt = "%H:%M:%S"
coloredlogs.install(level="DEBUG", fmt=fmt, datefmt=date_fmt,
                    field_styles={'levelname': {'bold': True, 'color': 'blue'},
                                  'asctime': {'color': 'green'}})
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
LIB_DUMP_CONFS = LIB_DUMP.joinpath("confs")


schema_cas = Schema(And(
    Use(dict),
    # Check that CA section contains at least one and maximum
    # two entries
    lambda l: 1 <= len(l.keys()) <= 3,  # noqa: E741
    {
        Optional("local_ca"): {
            Optional("dir", default=Path("/etc/SCAutolib/ca")): Use(Path)
        },
        Optional("ipa"): {
            'admin_passwd': Use(str),
            'root_passwd': Use(str),
            Optional('ip_addr', default=None): Use(str),
            'server_hostname': Use(str),
            'client_hostname': Use(str),
            'domain': Use(str),
            'realm': Use(str.upper)
        },
        Optional("custom"): [{
            'name': Use(str),
            'ca_cert': Use(str)
        }],
    }),
    ignore_extra_keys=True)

# Specify validation schema for all users
schema_user = Schema({
    'name': Use(str),
    'passwd': Use(str),
    'user_type': Or(UserType.local, UserType.ipa)
})

# Specify validation schema for all cards
schema_card = Schema({
    'name': Use(str),
    'pin': Use(str),
    Optional('label', default=None): Use(str),
    Optional('card_details', default=None): Use(str),
    'cardholder': Use(str),
    'CN': Use(str),
    Optional('UID', default=None): Use(str),
    Optional('expires', default=None): Use(str),
    'card_type': Or(CardType.virtual, CardType.physical),
    'ca_name': Use(str),
    Optional('slot', default=None): Use(str),
    Optional('uri', default=None): Use(str),
    Optional('cert', default=None): Use(str),
    Optional('key', default=None): Use(str)
})


def run(cmd: list[str], stdout: int = subprocess.PIPE,
        stderr: int = subprocess.PIPE, check: bool = True, log: bool = True,
        return_code: list = None, sleep: int = 0, **kwargs) \
        -> subprocess.CompletedProcess:
    """
    Executes an external command as a subprocess, providing a controlled
    wrapper around ``subprocess.run``. This function
    standardizes command execution, capturing and optionally printing output,
    performing robust error checking based on expected return codes, and
    provides consistent logging of what is being executed.

    :param cmd: The command to be executed, provided as a list of strings
                (preferred) or a single space-separated string.
    :type cmd: list or str
    :param stdout: Redirects the standard output of the command.
                   Accepts an int representing a file descriptor, or an
                   `IO object <https://docs.python.org/3/library/io.html>`__.
                   Defaults to ``subprocess.PIPE`` to capture output.
    :type stdout: None or int or IO
    :param stderr: Redirects the standard error of the command.
                   Accepts an int representing a file descriptor, or an
                   `IO object <https://docs.python.org/3/library/io.html>`__.
                   Defaults to ``subprocess.PIPE`` to capture output.
    :type stderr: None or int or IO
    :param check: If ``True``, the function will raise a
                  ``SCAutolibCommandFailed`` exception if the command's
                  return code is not in the ``return_code`` list. Defaults to
                  ``True``.
    :type check: bool
    :param log: If ``True``, the command's standard output will be logged at
                   DEBUG level and standard error at WARNING level. Defaults to
                   ``True``.
    :type log: bool
    :param return_code: A list of acceptable return codes for the command. If
                        ``check`` is ``True`` and the command's return code is
                        not in this list, an exception is raised. Defaults to
                        ``[0]``.
    :type return_code: list
    :param sleep: The duration in seconds to pause execution after the command
                  completes. Defaults to ``0``.
    :type sleep: int
    :param kwargs: Additional keyword arguments are passed directly to the
                   ``subprocess.run`` function.
    :raises SCAutolibCommandFailed: If ``check`` is ``True`` and the
                                    command's return code is not among
                                    the expected ``return_code`` values.
    :return: An object representing the completed process, including stdout,
             stderr, and return code.
    :rtype: SCAutolibCommandFailed
    """
    if return_code is None:
        return_code = [0]
    if isinstance(cmd, str):
        cmd = cmd.split(" ")
    logger.debug(f"run: {' '.join([str(i) for i in cmd])}")
    out = subprocess.run(cmd, stdout=stdout, stderr=stderr, encoding="utf-8",
                         **kwargs)
    if log:
        if out.stdout != "":
            logger.debug(out.stdout)
        if out.stderr != "":
            logger.warning(out.stderr)

    if check:
        if out.returncode not in return_code:
            logger.error(f"Unexpected return code {out.returncode}. "
                         f"Expected: {return_code}")
            raise SCAutolibCommandFailed(" ".join(cmd), out.returncode)
    time.sleep(sleep)
    return out
