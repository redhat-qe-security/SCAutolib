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


class PatternNotFound(Exception):
    def __init__(self,
                 msg: str = "Pattern not found in the output"):
        self.msg = msg
        super().__init__(msg)


class UnknownOption(Exception):
    def __init__(self,
                 option_name: str = "",
                 msg: str = "Unknow option is given",
                 option_val: str = None):
        self.msg = msg
        if option_name:
            self.msg += f": '{option_name}'"
        if option_val:
            self.msg += f" = {option_val}"
        super(UnknownOption, self).__init__(self.msg)


class DisallowedPatternFound(Exception):
    def __init__(self,
                 msg: str = "Disallowed pattern found in the output"):
        self.msg = msg
        super().__init__(msg)


class NonZeroReturnCode(Exception):
    def __init__(self,
                 msg: str = "Command exited with non zero return code"):
        self.msg = msg
        super().__init__(self.msg)
