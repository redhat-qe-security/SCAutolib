import logging
from sys import stdout


handler = logging.StreamHandler(stdout)
handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
handler.setFormatter(formatter)

# Basic logger
log = logging.getLogger("base")
log.setLevel(logging.DEBUG)

log.addHandler(handler)

# Logger for environment events
env = logging.getLogger("env")
env.setLevel(logging.DEBUG)

env.addHandler(handler)
