from .file import File


class SSSDConf(File):
    content = """Some default SSSD config content"""

    def replace(self, old: str, new: str):
        """
        Replace 'old' pattern with 'new' pattern in the file

        :param old:
        :param new:
        :return:
        """
    #   Define how to replace values in SSSD config file

    def set(self, key: str, value: str, section: str = None):
        """
        Set value in SSSD config file. Parameter 'section' has to be specified.
        """
