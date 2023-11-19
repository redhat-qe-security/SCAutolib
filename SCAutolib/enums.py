from enum import Enum, auto


class OSVersion(Enum):
    """
    Enumeration for Linux versions. Used for more convenient checks.
    """
    Fedora = 1
    RHEL_9 = 2
    RHEL_8 = 3
    CentOS_8 = 4
    CentOS_9 = 5


class CardType(str, Enum):
    physical = "physical"
    virtual = "virtual"


class UserType(str, Enum):
    local = "local"
    ipa = "ipa"


class CAType(str, Enum):
    local = "local"
    custom = "custom"
    ipa = "IPA"


class ReturnCode(Enum):
    """
    Enum for return codes
    """
    SUCCESS = 0
    MISSING_CA = auto()
    FAILURE = auto()
    ERROR = auto()
    EXCEPTION = auto()
    UNKNOWN = auto()
