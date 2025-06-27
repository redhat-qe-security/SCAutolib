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

    Members:
        * ``Fedora``: Represents the Fedora distribution.
            * Type: ``int``
            * Value: ``1``
        * ``RHEL_8``: Represents Red Hat Enterprise Linux version 8.
            * Type: ``int``
            * Value: ``2``
        * ``RHEL_9``: Represents Red Hat Enterprise Linux version 9.
            * Type: ``int``
            * Value: ``3``
        * ``RHEL_10``: Represents Red Hat Enterprise Linux version 10.
            * Type: ``int``
            * Value: ``4``
        * ``CentOS_8``: Represents CentOS version 8.
            * Type: ``int``
            * Value: ``5``
        * ``CentOS_9``: Represents CentOS version 9.
            * Type: ``int``
            * Value: ``6``
        * ``CentOS_10``: Represents CentOS version 10.
            * Type: ``int``
            * Value: ``7``
    """
    Fedora = 1
    RHEL_8 = 2
    RHEL_9 = 3
    RHEL_10 = 4
    CentOS_8 = 5
    CentOS_9 = 6
    CentOS_10 = 7


class CardType(str, Enum):
    """
    Enumeration for different types of smart cards supported by SCAutolib.
    This allows for clear categorization and differentiation in handling
    various card implementations within the library's logic.

    Members:
        * ``physical``: Represents a physical smart card, typically connected \
                        via a standard reader or specialized hardware like \
                        Removinator.
            * Type: ``str``
            * Value: `"physical"`
        * ``virtual``: Represents a virtual smart card, usually implemented \
                       in software (e.g., using SoftHSM2 or vicacard).
            * Type: ``str``
            * Value: `"virtual"`
    """
    physical = "physical"
    virtual = "virtual"


class UserType(str, Enum):
    """
    Enumeration for the types of users that can be managed and tested by
    SCAutolib. This distinguishes between local system users and users managed
    by an Identity Management (IdM) system like FreeIPA.

    Members:
        * ``local``: Represents a local user account on the system where \
                     SCAutolib is running.
            * Type: ``str``
            * Value: `"local"`
        * ``ipa``: Represents a user account managed by an IPA (Identity \
                   Management for Linux) server.
            * Type: ``str``
            * Value: `"ipa"`
    """
    local = "local"
    ipa = "ipa"


class CAType(str, Enum):
    """
    Enumeration for the different types of Certificate Authorities (CAs) that
    SCAutolib can interact with or configure.

    Members:
        * ``local``: Refers to a locally configured CA instance, often used for \
                     virtual smart cards.
            * Type: ``str``
            * Value: `"local"`
        * ``custom``: Refers to a custom or externally provided CA, typically \
                      associated with physical or read-only smart cards.
            * Type: ``str``
            * Value: `"custom"`
        * ``ipa``: Refers to a Certificate Authority integrated within an IPA \
                   (Identity Management for Linux) server.
            * Type: ``str``
            * Value: `"IPA"`
    """
    local = "local"
    custom = "custom"
    ipa = "IPA"


class ReturnCode(Enum):
    """
    Enumeration for standardized return codes used throughout SCAutolib
    to indicate the outcome of operations.
    These codes provide a clear and consistent way to signal success or
    various types of failures.

    Members:
        * ``SUCCESS``: Indicates that the operation completed successfully.
            * Type: ``int``
            * Value: ``0``
        * ``MISSING_CA``: Indicates that a required Certificate Authority \
                          (CA) is not configured on the system.
            * Type: ``auto`` (automatically assigned by ``enum.auto()``)
        * ``FAILURE``: Indicates a general failure during an operation.
            * Type: ``auto``
        * ``ERROR``: Indicates an error condition during an operation.
            * Type: ``auto``
        * ``EXCEPTION``: Indicates that an unhandled exception occurred.
            * Type: ``auto``
        * ``UNKNOWN``: Indicates an unknown return status or outcome.
            * Type: ``auto``
    """
    SUCCESS = 0
    MISSING_CA = auto()
    FAILURE = auto()
    ERROR = auto()
    EXCEPTION = auto()
    UNKNOWN = auto()
