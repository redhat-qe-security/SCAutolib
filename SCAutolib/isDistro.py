"""
This module provides a function (isDistro) that helps us identify the os
of the system and configure the system accordingly.
"""

import distro
from typing import Union


def isDistro(OSes: Union[str, list], version: str = None) -> bool:
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
