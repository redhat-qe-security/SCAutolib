from SCAutolib import logger
from contextlib import contextmanager
import re


@contextmanager
def assert_log(filename: str, expected_log: str):
    logger.info(f'Opening log file {filename}')
    with open(filename) as f:
        # Move file pointer to the end of file
        f.seek(0, 2)
        p = re.compile(expected_log)

        # Run the actual actions
        try:
            yield

        finally:
            logger.info(f'Asserting regex `{expected_log}` in {filename}')
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
