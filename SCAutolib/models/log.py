from SCAutolib import logger
from contextlib import contextmanager
import re


@contextmanager
def assert_log(path: str, expected_log: str):
    """Asserts, that a new line in log is created, that matches given regex.

    :param path: Path to the file, that will be checked for added logs.
    :param expected_log: Regular expression
        that has to match one of the new logs.

    When the context manager starts, the log file is skipped until the end
    to ignore any previous logs.
    Then the action inside the context manager is run.
    This action should generate some logs.
    When the context manager exits,
    newly generated logs are matched to the regular expression.
    In case none of the logs match, an exception is raised.
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
