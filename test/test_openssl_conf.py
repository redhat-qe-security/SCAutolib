"""
This module contains unit tests for OpensslCnf
"""
from pathlib import Path

from SCAutolib.models.file import OpensslCnf
from conftest import FILES_DIR
from test_sssd_conf import compare_conf_files


def test_create(tmpdir):
    reference_file = Path(FILES_DIR, "openssl_cnf_test_result")
    tmpfile = Path(tmpdir, "testfile")
    opensslcnf_test = OpensslCnf(filepath=tmpfile, conf_type="user",
                                 replace=["test_user_123", "test_cn"])
    opensslcnf_test.create()
    opensslcnf_test.save()
    compare_conf_files(opensslcnf_test._conf_file, reference_file)
