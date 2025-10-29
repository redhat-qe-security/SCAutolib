"""
This module defines various enumeration classes used throughout the SCAutolib
library. These enumerations provide a set of
named constants, enhancing code readability, maintainability, and reducing
the likelihood of errors by restricting values to a predefined set.
"""


from enum import Enum, auto


class OSVersion(int, Enum):
    """
    Enumeration for Linux operating system versions.
    This class provides a convenient way to represent and check different
    Linux distributions and their major versions numerically within SCAutolib's
    logic.
    """

    Fedora = 1  # Fedora distribution
    RHEL_8 = 2  # Red Hat Enterprise Linux version 8
    RHEL_9 = 3  # Red Hat Enterprise Linux version 9
    RHEL_10 = 4  # Red Hat Enterprise Linux version 10
    CentOS_8 = 5  # CentOS version 8
    CentOS_9 = 6  # CentOS version 9
    CentOS_10 = 7  # CentOS version 10


class CardType(str, Enum):
    """
    Enumeration for different types of smart cards supported by SCAutolib.
    This allows for clear categorization and differentiation in handling
    various card implementations within the library's logic.
    """

    physical = "physical"  # physical smart card, connected via reader
    virtual = "virtual"  # virtual smart card, usually implemented in software


class UserType(str, Enum):
    """
    Enumeration for the types of users that can be managed and tested by
    SCAutolib. This distinguishes between local system users and users managed
    by an Identity Management (IdM) system like FreeIPA.
    """

    local = "local"  # local user account on the system
    ipa = "ipa"  # user account managed by an IPA server


class CAType(str, Enum):
    """
    Enumeration for the different types of Certificate Authorities (CAs) that
    SCAutolib can interact with or configure.
    """

    local = "local"  # locally configured CA instance
    custom = "custom"  # custom or externally provided CA
    ipa = "IPA"  # Certificate Authority integrated within an IPA server


class ReturnCode(Enum):
    """
    Enumeration for standardized return codes used throughout SCAutolib
    to indicate the outcome of operations.
    These codes provide a clear and consistent way to signal success or
    various types of failures.
    """

    SUCCESS = 0  # operation completed successfully
    FAILURE = auto()  # general failure during an operation
    MISSING_CA = auto()  # required CA is not configured on the system
    ERROR = auto()  # error condition during an operation
    EXCEPTION = auto()  # an unhandled exception occurred
    UNKNOWN = auto()  # unknown return status or outcome
