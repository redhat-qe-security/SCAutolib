import logging
from sys import stdout


class __Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


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
