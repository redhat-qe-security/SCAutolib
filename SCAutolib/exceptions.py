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


class SCAutolibMissingCA(SCAutolibException):
    default = "CA is not configured on the system"

    def __init__(self, msg=None):
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibMissingUserConfig(SCAutolibException):
    def __init__(self, name):
        msg = f"User {name} is found in config file"
        super().__init__(msg)
