"""
Exceptions that are used in the SCAutolib library.
This module defines a hierarchy of custom exception classes that are
raised by SCAutolib components to signal specific error conditions
during operations. These custom exceptions
provide more specific context than generic Python exceptions,
aiding in error handling and debugging.
"""


class SCAutolibException(Exception):
    """
    Base exception class for all custom exceptions within SCAutolib.
    All other SCAutolib-specific exceptions inherit from this class,
    allowing for a unified way to catch any error originating from the library.
    """
    def __init__(self, *args):
        super().__init__(*args)


class SCAutolibWrongConfig(SCAutolibException):
    """
    Exception raised when a required key or section is missing or is
    incorrectly configured in the application's configuration file.
    This signals that the current operation cannot proceed due to an invalid
    or incomplete configuration setup.
    """
    default = "Key/section for current operation is not present in the " \
              "configuration file"

    def __init__(self, msg=None):
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibMissingCA(SCAutolibException):
    """
    Exception raised when a Certificate Authority (CA) required for an
    operation is not configured on the system. This typically
    occurs if a smart card enrollment or certificate request is attempted
    without a proper CA setup.
    """
    default = "CA is not configured on the system"

    def __init__(self, msg=None):
        msg = self.default if msg is None else msg
        super().__init__(msg)


class SCAutolibMissingUserConfig(SCAutolibException):
    """
    Exception raised when a user, specified by their name, is expected to
    be found in the configuration file but is not present.
    This indicates that the library cannot proceed with operations for the
    requested user due to missing configuration.
    """
    def __init__(self, name):
        msg = f"User {name} is found in config file"
        super().__init__(msg)
