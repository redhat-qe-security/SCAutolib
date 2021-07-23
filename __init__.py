import logging
from sys import stdout

handler = logging.StreamHandler(stdout)
handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - SCAutolib:%(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
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
