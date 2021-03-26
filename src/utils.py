import shutil
import subprocess as subp
from os import path

from SCAutolib import log

FILE_PATH = path.dirname(path.realpath(__file__))
SERVICES = {"sssd": "/etc/sssd/sssd.conf", "krb": "/etc/krb5.conf"}
DEFAULTS = {"sssd": f"{FILE_PATH}/env/conf/sssd.conf"}


def config_variants(service, variants, section):
    def wrapper(test):
        def inner_wrapper(*args):
            for var in variants:
                if var == "":  # default variant
                    test(args)
                    continue
                # change config
                edit_config(SERVICES[service], var, section)
                # restart service
                restart_service(service)
                # run test
                test(args)
                # restore config
                restore_config(service)

        return inner_wrapper

    return wrapper


def _edit_config(config, string, section):
    with open(config, "r") as file:
        content = file.read()
    content = content.replace(f"#<{section}>", f"{string}\n#<{section}>")
    with open(config, "w+") as file:
        file.write(content)
    # TODO how to check if there was some errors?
    log.debug(f"File {config} is updated")


def edit_config(service, string, section):
    def wrapper(test):
        def inner_wrapper(*args):
            _edit_config(SERVICES[service], string, section)
            restart_service(service)
            test(args)
            # restore_config(service)

        return inner_wrapper

    return wrapper


def get_slots() -> str:
    # TODO get all slots with active cards
    result = subp.run(["pkcs11-tool", "--list--slots"], text=True, capture_output=True)
    slots = result.stdout.decode("utf8")
    return slots


def restart_service(service):
    subp.run(["systemctl", "restart", f"{service}"], check=True)
    log.debug(f"Service {service} is restarted")
    # FIXME do I need to work with ant exceptions here?


def restore_config(service=None):
    shutil.copyfile(DEFAULTS[service], SERVICES[service])
    log.debug(f"File {SERVICES[service]} is restored")
