"""
This module contains unit tests for SSSDConf and related functions

The unit test name reflects name of tested sssd_conf method. For example
'test_create_template_exists' is unit test for method 'create' of sssd_conf.
"""
import configparser
import pathlib
import shutil
from configparser import ConfigParser
from pathlib import Path

import pytest

from SCAutolib.models.file import SSSDConf
from conftest import FILES_DIR


def load_file_to_parser(config_file: pathlib.Path):
    """
    Instantiate parser object and update it with content of config file

    :param config_file: path to config file
    :return: parser object
    """
    parser = ConfigParser()
    parser.optionxform = str
    with config_file.open() as f1:
        parser.read_file(f1)
    return parser


def parser_object_to_dict(parser_object: configparser.ConfigParser):
    """
    Transform content of parser object to dictionary

    :param parser_object: object to be transformed
    :return: dictionary reflecting content of parser object
    """
    content = {section: dict(parser_object.items(section)) for section in
               parser_object.sections()}
    return content


def compare_conf_files(file1: pathlib.Path, file2: pathlib.Path):
    """
    Compare content of two config files ignoring empty lines and reshuffling
    of content

    :param file1:  first of compared files
    :param file2:  second of compared files
    :return: True if content of files matches, False otherwise
    """
    dict1 = parser_object_to_dict(load_file_to_parser(file1))
    dict2 = parser_object_to_dict(load_file_to_parser(file2))
    assert dict1 == dict2


# TESTS
def test_check_backups(tmpdir):
    """
    Exception is raised if backup file exists
    """
    tmpfile = Path(tmpdir, "testfile")
    tmpfile.touch()
    sssd = SSSDConf()
    sssd._backup_default = tmpfile
    sssd._backup_original = tmpfile
    with pytest.raises(FileExistsError, match=f'{tmpfile} file exists'):
        sssd.check_backups()


def test_create_content_backup_original(sssd_test_prepare):
    """
    Backup of original config file is created if the file exists
    Backup of library default conf_file is created
    """
    sssd_test = sssd_test_prepare

    # create conf
    shutil.copy2(SSSDConf._template, sssd_test._conf_file)
    sssd_test.create()

    assert sssd_test._backup_default.exists()
    compare_conf_files(SSSDConf._template, sssd_test._backup_default)


def test_create_conf_updated(sssd_test_prepare):
    """
    Content of config file is updated with values from template
    if the file already exists
    """
    # create content of config based on test config file; load content to dict
    sssd_test = sssd_test_prepare
    sssd_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")

    sssd_test.create()

    # load reference content from library file to parser object
    reference_file = Path(FILES_DIR, "sssd_conf_test_result")
    reference_content = load_file_to_parser(reference_file)

    assert parser_object_to_dict(sssd_test._default_parser) == \
           parser_object_to_dict(reference_content)


def test_set_conf_add_value(sssd_test_prepare):
    """
    Tests that new value is added to existing section
    """
    sssd_test = sssd_test_prepare
    sssd_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")
    # load some content to parser object
    with sssd_test._conf_file.open() as config:
        sssd_test._default_parser.read_file(config)
    sssd_test.set("newkey", "newvalue", "testsection")
    assert sssd_test._changes["testsection"]["newkey"] == "newvalue"


def test_set_conf_add_section(sssd_test_prepare):
    """
    Tests that section is added with key and value if the section was not
    present
    """
    sssd_test = sssd_test_prepare
    sssd_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")
    # load some content to parser object
    with sssd_test._conf_file.open() as config:
        sssd_test._default_parser.read_file(config)
    sssd_test.set("newkey", "newvalue", "newsection")
    assert sssd_test._changes["newsection"]["newkey"] == "newvalue"


def test_set_conf_overwrite_value(sssd_test_prepare):
    """
    Tests that value in is overwritten if section and key already existed
    """
    sssd_test = sssd_test_prepare
    sssd_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")
    # load some content to parser object
    with sssd_test._conf_file.open() as config:
        sssd_test._default_parser.read_file(config)
    sssd_test.set("testkey", "overwrite", "testsection")
    assert sssd_test._changes["testsection"]["testkey"] == "overwrite"


def test_save_reset_parser(sssd_test_prepare):
    """
    Test that save method saves config file and reset parser object
    """
    sssd_test = sssd_test_prepare
    sssd_test.set("testkey", "overwrite", "testsection")
    sssd_test.save()
    assert sssd_test._conf_file.exists()
    assert len(sssd_test._changes.sections()) == 0


@pytest.mark.service_restart
def test_context_manager(tmpdir, sssd_test_prepare):
    """
    Test that context manager works as expected
    """
    call_key, call_value, call_section = "testkey", "testvalue", "testsection"
    sssd_test_prepare._backup_default.touch(exist_ok=True)

    with sssd_test_prepare(key=call_key, value=call_value, section=call_section):
        parser = ConfigParser()
        with sssd_test_prepare._conf_file.open() as config:
            parser.read_file(config)
        assert parser.get(call_section, call_key) == call_value

    with sssd_test_prepare._conf_file.open() as config:
        parser = ConfigParser()
        parser.read_file(config)
        with pytest.raises(configparser.NoSectionError):
            parser.get(call_section, call_key)
