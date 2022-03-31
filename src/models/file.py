from pathlib import Path


class File:
    path: Path = None
    content: str = None

    def __init__(self):
        # create a file if not created
        ...

    def set(self, key: str, value: str, section: str = None):
        """

        :param key:
        :param value:
        :param section:
        :return:
        """

    def get(self):
        ...

    def backup(self) -> Path:
        """
        Backup file
        :return: path to back up file
        """
        ...

    def restore(self):
        """Restore file from the last backup"""
        ...
