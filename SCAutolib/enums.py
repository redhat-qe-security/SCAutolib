"""
Define enumeration classes for the SCAutolib library.

These enumerations provide a set of named constants to enhance code
readability and maintainability while restricting values to predefined sets.
"""


from enum import Enum, auto


class OSVersion(int, Enum):
    """
    Represent Linux operating system versions.

    Used to numerically identify and check different Linux distributions
    and their major versions within SCAutolib's logic.
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
    Categorize smart card implementations supported by SCAutolib.

    Distinguishes between physical hardware cards and software-based
    virtual cards.
    """

    physical = "physical"  # physical smart card, connected via reader
    virtual = "virtual"  # virtual smart card, usually implemented in software


class UserType(str, Enum):
    """
    Identify the origin of user accounts managed by SCAutolib.

    Distinguishes between local system accounts and accounts managed
    by an Identity Management (IdM) system like FreeIPA.
    """

    local = "local"  # local user account on the system
    ipa = "ipa"  # user account managed by an IPA server


class CAType(str, Enum):
    """
    Represent types of Certificate Authorities (CAs) used in the library.

    Provides consistent CA types of local, custom, or IPA.
    """

    local = "local"  # locally configured CA instance
    custom = "custom"  # custom or externally provided CA
    ipa = "IPA"  # Certificate Authority integrated within an IPA server


class ReturnCode(Enum):
    """
    Standardize operation outcomes across SCAutolib.

    Provides a consistent set of codes to signal success, configuration
    issues, or runtime errors.
    """

    SUCCESS = 0  # operation completed successfully
    FAILURE = auto()  # general failure during an operation
    MISSING_CA = auto()  # required CA is not configured on the system
    ERROR = auto()  # error condition during an operation
    EXCEPTION = auto()  # an unhandled exception occurred
    UNKNOWN = auto()  # unknown return status or outcome
