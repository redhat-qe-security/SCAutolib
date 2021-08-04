
class SCAutolibException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class NonZeroReturnCode(SCAutolibException):
    def __init__(self, cmd=None, msg: str = "Command exited with non zero return code"):
        self.msg = msg
        self.cmd = cmd
        super().__init__(self.msg)


class PatternNotFound(SCAutolibException):
    def __init__(self, pattern, msg: str = "Pattern not found in the output"):
        self.msg = msg
        self.pattern = pattern
        super().__init__(self.msg)
