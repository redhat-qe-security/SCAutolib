
class SCAutolibException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class NonZeroReturnCode(SCAutolibException):
    def __init__(self, msg: str = "Command exited with non zero return code"):
        self.msg = msg
        super().__init__(self.msg)


class PatternNotFound(SCAutolibException):
    def __init__(self, msg: str = "Pattern not found in the output"):
        self.msg = msg
        super().__init__(msg)


class DisallowedPatternFound(SCAutolibException):
    def __init__(self, msg: str = "Disallowed pattern found in the output"):
        self.msg = msg
        super().__init__(msg)


class UnspecifiedParameter(SCAutolibException):
    def __init__(self, parameter: str = None, msg: str = "Parameter is not specified"):
        self.msg = msg
        self.parameter = parameter
        if self.parameter is not None:
            msg += f" for parameter {self.parameter}"
        super().__init__(self.msg)
