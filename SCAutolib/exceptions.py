"""
Define custom exceptions for the SCAutolib library.

This module provides a hierarchy of exception classes used to signal
specific error conditions, offering more context than generic Python
exceptions to aid in debugging and error handling.
"""


class SCAutolibException(Exception):
    """
    Base class for all custom exceptions within SCAutolib.

    Inherit from this class to allow a unified way to catch any error
    originating specifically from this library.
    """

    def __init__(self, *args):
        """
        Initialize the base exception.

        :param args: Variable length argument list.
        :type args: Any
        :return: None
        """
        super().__init__(*args)


class SCAutolibGUIException(SCAutolibException):
    """
    Signal an error encountered within the graphical environment.
    """

    default = "Graphical environment encountered and error"

    def __init__(self, msg=None):
        """
        Initialize the GUI exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibIPAException(SCAutolibException):
    """
    Signal an error encountered during IPA-related functions.
    """

    default = "IPA setup encountered and error"

    def __init__(self, msg=None):
        """
        Initialize the IPA exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibWrongConfig(SCAutolibException):
    """
    Raise when a required configuration key or section is missing or invalid.
    """

    default = "Key/section for current operation is not present in the " \
              "configuration file"

    def __init__(self, msg=None):
        """
        Initialize the configuration exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibMissingCA(SCAutolibException):
    """
    Raise when a required Certificate Authority is not configured.
    """

    default = "CA is not configured on the system"

    def __init__(self, msg=None):
        """
        Initialize the missing CA exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibMissingUserConfig(SCAutolibException):
    """
    Raise when a user configuration is missing.
    """

    def __init__(self, name):
        """
        Initialize the missing user configuration exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = f"User {name} is found in config file"
        super().__init__(msg)


class SCAutolibFileExists(SCAutolibException):
    """
    Raise when attempting to create a file that already exists.
    """

    default = "The file already exists"

    def __init__(self, msg=None):
        """
        Initialize the file exists exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibFileNotExists(SCAutolibException):
    """
    Raise when a required file is missing from the filesystem.
    """

    default = "The file does not exists"

    def __init__(self, msg=None):
        """
        Initialize the file not found exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibNoTemplate(SCAutolibException):
    """
    Raise when no template file is provided for a creation operation.
    """

    default = "No template was provided for the file to be created"

    def __init__(self, msg=None):
        """
        Initialize the missing template exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibUnknownType(SCAutolibException):
    """
    Raise when a provided value does not match expected enumeration types.
    """

    default = "Unknown type"

    def __init__(self, msg=None):
        """
        Initialize the unknown type exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibNotFound(SCAutolibException):
    """
    Raise when an expected search result or object is not found.
    """

    default = "Expected result is not found"

    def __init__(self, msg=None):
        """
        Initialize the not found exception.

        :param msg: Custom error message.
        :type msg: str, optional
        :return: None
        """
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibCommandFailed(SCAutolibException):
    """
    Raise when a system command returns an unexpected exit code.
    """

    default = "Command failed with unexpected code."

    def __init__(self, cmd: str = None, ret_code: int = None):
        """
        Initialize the command failure exception.

        :param cmd: The command string that was executed.
        :type cmd: str, optional
        :param ret_code: The exit code returned by the system.
        :type ret_code: int, optional
        :return: None
        """
        if cmd and ret_code:
            msg = f"Command '{cmd}' returned unexpected code {ret_code}."
        else:
            msg = self.default
        super().__init__(msg)
