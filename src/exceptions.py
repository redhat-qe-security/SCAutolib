
class SCAutolibException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class NonZeroReturnCode(Exception):
    def __init__(self, cmd=None, msg: str = "Command exited with non zero return code"):
        self.msg = msg
        self.cmd = cmd
        super().__init__(self.msg)


class PatternNotFound(Exception):
    def __init__(self, msg: str = "Pattern not found in the output", pattern=None):
        super().__init__(msg)
        self.msg = msg
        self.pattern = pattern

class NoDirProvided(Exception):
    def __init__(self, parameter: str = None, msg: str = "No directory is provided"):
        self.msg = msg
        self.parameter = parameter
        if self.parameter is not None:
            msg += f" for parameter {self.parameter}"
        super().__init__(self.msg)
