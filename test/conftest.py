from os import environ
from shutil import rmtree
import logging
import os
from subprocess import check_output, CalledProcessError

from SCAutolib import LIB_DIR
from fixtures import *  # noqa: F401

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(DIR_PATH, "files")
LOGGER = logging.getLogger("pytest-custom")


def pytest_addoption(parser):
    """
    Define CLI parameters. Parameters for IPA would be serialised to ipa_config
    fixture.
    """
    parser.addoption(
        "--ipa-ip", action="store", help="IP address of IPA server",
        default=environ["IPA_IP"]
    )
    parser.addoption(
        "--ipa-hostname", action="store", help="Hostname of IPA server",
        default=environ["IPA_HOSTNAME"]
    )
    parser.addoption(
        "--ipa-admin-passwd", action="store",
        default=environ["IPA_ADMIN_PASSWD"],
        help="Admin password for IPA server (for kinit)"
    )
    parser.addoption(
        "--ipa-root-passwd", action="store", default=environ["IPA_ROOT_PASSWD"],
        help="Root password for IPA server (for SSH)"
    )


def pytest_generate_tests(metafunc):
    """
    Inject variables to test. Variables should be specified in test arguments
    """
    ipa_ip = metafunc.config.option.ipa_ip
    ipa_hostname = metafunc.config.option.ipa_hostname
    ipa_admin_passwd = metafunc.config.option.ipa_admin_passwd
    ipa_root_passwd = metafunc.config.option.ipa_root_passwd

    if 'ipa_config' in metafunc.fixturenames \
            and all([ipa_ip, ipa_hostname, ipa_admin_passwd, ipa_root_passwd]):
        ipa_config = {"ip": ipa_ip, "hostname": ipa_hostname,
                      "admin_passwd": ipa_admin_passwd,
                      "root_passwd": ipa_root_passwd}
        metafunc.parametrize("ipa_config", [ipa_config])

    if 'ipa_ip' in metafunc.fixturenames and ipa_ip is not None:
        metafunc.parametrize("ipa_ip", [ipa_ip], scope="session")
    if 'ipa_hostname' in metafunc.fixturenames and ipa_hostname is not None:
        metafunc.parametrize("ipa_hostname", [ipa_hostname], scope="session")
    if 'ipa_admin_passwd' in metafunc.fixturenames \
            and ipa_admin_passwd is not None:
        metafunc.parametrize("ipa_admin_passwd", [ipa_admin_passwd],
                             scope="session")
    if 'ipa_root_passwd' in metafunc.fixturenames \
            and ipa_root_passwd is not None:
        metafunc.parametrize("ipa_root_passwd", [ipa_root_passwd],
                             scope="session")


def pytest_sessionstart(session):
    LIB_DIR.mkdir(exist_ok=True, parents=True)


def pytest_sessionfinish(session, exitstatus):
    """
    Change behaviour: if no tests found (exit status == 5), for us, it is not a
    fail.
    """
    rmtree(LIB_DIR)
    if any("ipa" in i.originalname for i in session.items):
        LOGGER.info("IPA test was called. Trying to remove IPA client")
        try:
            check_output(["ipa-client-install", "--uninstall", "--unattended"],
                         encoding="utf-8")
        except CalledProcessError:
            LOGGER.info("Can't uninstall IPA client")

    if exitstatus == 5:
        LOGGER.info("Changing exit status from 5 to 0")
        session.exitstatus = 0
