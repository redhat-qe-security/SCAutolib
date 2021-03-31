import shutil
import subprocess as subp
from os import path
from random import randint

from OpenSSL import crypto

from SCAutolib import log

DIR_PATH = path.dirname(path.abspath(__file__))
SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
DEFAULTS = {"sssd": f"{DIR_PATH}/env/conf/sssd.conf"}


def edit_config(service, string, section):
    def wrapper(test):
        def inner_wrapper(*args):
            _edit_config(SERVICES[service], string, section)
            restart_service(service)
            test(args)
            restore_config(service)
            restart_service(service)

        return inner_wrapper

    return wrapper


def _edit_config(config, string, section):
    holder = f"#<{section}>"
    with open(config, "r") as file:
        content = file.read()
        if holder not in content:
            log.error(f"File {config} is not updated. "
                      f"Maybe placeholder in the config {config} "
                      f"for the section {section} is missing?")
            raise Exception(f"Placeholder {holder} is not present in {config}")

    content = content.replace(holder, f"{string}\n{holder}")
    with open(config, "w+") as file:
        file.write(content)

    log.debug(f"Section {section} if config file {config} is updated")


def restart_service(service):
    try:
        subp.run(["systemctl", "restart", f"{service}"], check=True, encoding="utf8")
        log.debug(f"Service {service} is restarted")
    except subp.CalledProcessError as e:
        log.error(f"Command {e.cmd} is ended with non-zero return code ({e.returncode})")
        log.error(f"stdout:\n{e.stdout}")
        log.error(f"stderr:\n{e.stderr}")
    except Exception as e:
        log.error(f"Unexpected exception is raised: {e}")
        raise e


def restore_config(service=None):
    try:
        shutil.copyfile(DEFAULTS[service], SERVICES[service])
        log.debug(f"File {SERVICES[service]} is restored")
    except shutil.SameFileError:
        log.debug(f"Source file {DEFAULTS[service]} and destination file {SERVICES[service]} are the same")
    except Exception as e:
        log.error(f"Unexpected exception is raised: {e}")
        log.error(f"File {SERVICES[service]} is not restored")
        raise e
