"""
This module provides a context manager, ``assert_log``, designed for verifying
the presence of specific log entries in a file during test execution.

It allows for asserting that a given regular expression matches a newly
generated log line within a specified log file.
"""


from SCAutolib import logger
from contextlib import contextmanager
import re


@contextmanager
def assert_log(path: str, expected_log: str):
    """
    A context manager that asserts the creation of a new log line in a
    specified file that matches a given regular expression.

    When entering the context, the log file's pointer is moved to its end to
    ignore any existing logs. The code block within the
    ``with`` statement is then executed. Upon exiting the context (either
    normally or due to an exception), the function reads new log entries and
    attempts to find a match for the ``expected_log`` regular expression.

    If no matching log is found among the newly generated entries, an exception
    is raised.

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

            for line in f:
                log += line
                m = p.match(line)
                if m:
                    # found the log
                    text = m.group()
                    logger.info(f'Found matching line: {text}')
                    return

            logger.debug(log)
            raise Exception('The log was not found.')
