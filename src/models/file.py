from pathlib import Path


class File:
    path: Path = None
    content: str = None

    def __init__(self):
        # create a file if not created
        ...

    def replace(self, old: str, new: str):
        """
        Replace 'old' pattern with 'new' pattern in the file

        :param old:
        :param new:
        :return:
        """

    def set(self, key: str, value: str, *args, **kwargs):
        """

        :param key:
        :param value:
        :param args:
        :param kwargs:
        :return:
        """

    def backup(self) -> Path:
        """
        Backup file
        :return: path to backup file
        """

    def restore(self):
        """Restore file from the last backup"""
