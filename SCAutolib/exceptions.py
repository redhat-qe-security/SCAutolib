"""
Exceptions that are used in the SCAutolib
"""


class SCAutolibException(Exception):
    """
    Base SCAutolib exception
    """
    def __init__(self, *args):
        super().__init__(*args)


class SCAutolibWrongConfig(SCAutolibException):
    default = "Key/section for current operation is not present in the " \
              "configuration file"

    def __init__(self, msg=None):
        msg = self.default if msg is None else msg
        super().__init__(msg)
