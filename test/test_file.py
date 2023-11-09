"""
This module contains unit tests for file.py and related functions
"""
import filecmp
import shutil
from pathlib import Path

import pytest

from SCAutolib.models.file import SSSDConf
from conftest import FILES_DIR
from test_sssd_conf import compare_conf_files


def test_create_fail(file_test_prepare):
    """
    Exception is raised if conf file already exists
    """
    file_test = file_test_prepare
    with file_test._conf_file.open('w') as config:
        config.write('Test config file')
    with pytest.raises(FileExistsError, match=f'{file_test._conf_file} '
                                              f'already exists'):
        file_test.create()


def test_create(file_test_prepare):
    """
    Content of config file is created based on template if the file is not
    present in the system.
    """
    file_test = file_test_prepare
    file_test._template = SSSDConf._template
    file_test.create()
    # save content to file so it can easily be compared
    file_test.save()
    compare_conf_files(SSSDConf._template, file_test._conf_file)


def test_set_add_value(file_test_prepare):
    """
    Tests that new value is added to existing section
    """
    file_test = file_test_prepare
    file_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")
    file_test.set("newkey", "newvalue", "testsection")
    assert file_test._default_parser["testsection"]["newkey"] == "newvalue"


def test_set_add_section(file_test_prepare):
    """
    Tests that section is added with key and value if the section wasn't present
    """
    file_test = file_test_prepare
    file_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")
    file_test.set("newkey", "newvalue", "newsection")
    assert file_test._default_parser["newsection"]["newkey"] == "newvalue"


def test_set_overwrite_value(file_test_prepare):
    """
    Tests that value in is overwritten if section and key already existed
    """
    file_test = file_test_prepare
    file_test._conf_file = Path(FILES_DIR, "sssd_conf_test_start")
    file_test.set("testkey", "overwrite", "testsection")
    assert file_test._default_parser["testsection"]["testkey"] == "overwrite"


def test_set_simple_content(file_test_prepare):
    """
    Tests that value in is overwritten if section and key already existed
    """
    file_test = file_test_prepare
    test_start = Path(FILES_DIR, "conf_file_start")
    shutil.copy2(test_start, file_test._conf_file)

    file_test.set("prompt", "newprompt")
    file_test.set("OU", "testvalue")
    file_test.set("newkey", "newvalue")
    file_test.save()

    test_result = Path(FILES_DIR, "conf_file_end")
    assert filecmp.cmp(test_result, file_test._conf_file, shallow=False)
