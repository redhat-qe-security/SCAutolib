import logging
from sys import stdout

handler = logging.StreamHandler(stdout)
handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('(%(filename)s) %(module)s.%(funcName)s.%(lineno)d:%(levelname)s - %(message)s',)
handler.setFormatter(formatter)

# Basic logger
log = logging.getLogger("base")
log.setLevel(logging.DEBUG)
log.addHandler(handler)

# Logger for environment events
env_logger = logging.getLogger("env")
env_logger.setLevel(logging.DEBUG)
env_logger.addHandler(handler)


def hello():
    print("Hello. Just check that it is imported")
