from .file import File


class SoftHSM2Conf(File):
    def replace(self, old: str, new: str):
        """
        Replace 'old' pattern with 'new' pattern in the file

        :param old:
        :param new:
        :return:
        """
    #   Define how to replace values in SoftHSM2 config file

    def set(self, key: str, value: str, section: str = None):
        """
        Add content to SoftHSM2 config files

        """
