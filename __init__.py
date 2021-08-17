import logging
import coloredlogs


fmt = '%(module)s.%(funcName)s.%(lineno)d [%(levelname)s] %(message)s'

# Basic logger
log = logging.getLogger("base")

# Logger for environment events
env_logger = logging.getLogger("env")
color_dict = {'critical': {'bold': True, 'color': 'red'},
              'debug': {'color': 'green'},
              'error': {'color': 'red'},
              'info': {},
              'notice': {'color': 'magenta'},
              'spam': {'color': 'green', 'faint': True},
              'success': {'bold': True, 'color': 'green'},
              'verbose': {'color': 'blue'},
              'warning': {'color': 'yellow'}}

color_dict_fields = {'levelname': {'color': 'white', "bright": True},
                     "module": {"color": 63}}

coloredlogs.install(level='DEBUG', logger=env_logger, fmt=fmt, field_styles=color_dict_fields, level_styles=color_dict)
coloredlogs.install(level='DEBUG', logger=log, fmt=fmt, field_styles=color_dict_fields, level_styles=color_dict)


def hello():
    print("Hello. Just check that it is imported")
