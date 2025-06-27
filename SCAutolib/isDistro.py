"""
This module provides a utility function, ``isDistro``, designed to identify
the operating system distribution and its version.
This functionality helps SCAutolib to dynamically configure
system settings or install packages based on the specific Linux distribution
it's running on.
"""


import distro
from typing import Union


def isDistro(OSes: Union[str, list], version: str = None) -> bool:
    """
    Identifies if the current operating system matches a specified distribution
    and, optionally, its version. This function leverages the ``distro`` library
    to determine the system's ID, name, and version details.

    :param OSes: The ID or name of the operating system(s) to check against.
                 Can be a single string (e.g., "fedora", "rhel") or a list of
                 strings. Case-insensitive comparison is performed.
    :type OSes: Union[str, list]
    :param version: An optional string specifying the version to check. It can
                    include comparison operators
                    (``<``, ``<=``, ``==``, ``>``, ``>=``).
                    If no operator is specified, ``==`` is assumed.
                    Examples: "8", ">=9", "<39".
    :type version: str, optional
    :return: ``True`` if the current operating system matches the specified
             distribution(s) and version criteria; ``False`` otherwise.
    :rtype: bool
    """

    cur_id = distro.id().lower()
    cur_name = distro.name().lower()

    if isinstance(OSes, str):
        results = (OSes in cur_id) or (OSes in cur_name)
    else:
        results = False
        for item in OSes:
            if not isinstance(item, str):
                continue
            item = item.lower()
            results = results or (item in cur_id) or (item in cur_name)

    if results is False:
        return False

    if version:
        cur_major = int(distro.major_version())
        cur_minor = int(distro.minor_version()) if distro.minor_version() else 0

        if version[0] in ('<', '=', '>'):
            if version[1] == '=':
                op = version[:2]
                version = version[2:]
            else:
                op = version[0] if version[0] != '=' else '=='
                version = version[1:]
        else:
            op = '=='

        parts = version.split('.')
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else None

        if major == cur_major and minor:
            return eval("{0} {1} {2}".format(cur_minor, op, minor))
        else:
            return eval("{0} {1} {2}".format(cur_major, op, major))

    return True
