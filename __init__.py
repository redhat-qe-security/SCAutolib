import colorlog

handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    '%(log_color)s%(module)s.%(funcName)s.%(lineno)d [%(levelname)s] %(message)s',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white'})
handler.setFormatter(formatter)

# Basic logger
base_logger = colorlog.getLogger("base")
base_logger.addHandler(handler)
base_logger.setLevel(colorlog.DEBUG)

# Logger for environment events
env_logger = colorlog.getLogger("env")
env_logger.addHandler(handler)
env_logger.setLevel(colorlog.DEBUG)


def hello():
    print("Hello. Just check that SCAutolib is imported")
