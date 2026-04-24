"""
Verify the presence of specific log entries in a file.

This module provides the ``assert_log`` context manager, which is used
during test execution to verify that a given regular expression matches
a newly generated log line within a specified log file.
"""


from SCAutolib import logger
from SCAutolib.exceptions import SCAutolibNotFound
from contextlib import contextmanager
import re


@contextmanager
def assert_log(path: str, expected_log: str):
    """
    Assert that a new log line matches a regular expression.

    When entering the context, the file pointer moves to the end to ignore
    existing logs. Upon exit, the function reads any new entries and
    searches for a match against the ``expected_log`` regex.

    :param path: The string path to the log file that will be monitored
                 for new log entries.
    :type path: str
    :param expected_log: The regular expression string that is expected to
                         match one of the new log lines generated within the
                         context.
    :type expected_log: str
    :yield: None. This is a context manager, so it yields control to the
            ``with`` block.
    :raises Exception: If no new log line matches the ``expected_log`` regular
                       expression by the time the context is exited.
    """
    logger.info(f'Opening log file {path}')
    with open(path) as f:
        # Move file pointer to the end of file
        f.seek(0, 2)
        p = re.compile(expected_log)

        # Run the actual actions
        try:
            yield

        finally:
            logger.info(f'Asserting regex `{expected_log}` in {path}')
            log = ''  # Only for debugging purposes

            found = False
            for line in f:
                log += line
                m = p.match(line)
                if m:
                    # found the log
                    text = m.group()
                    logger.info(f'Found matching line: {text}')
                    found = True
                    break

            if not found:
                logger.debug(log)
                raise SCAutolibNotFound('The log was not found.')
