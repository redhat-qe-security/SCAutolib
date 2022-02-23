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

    def set(self, key: str, value: str, *args, **kwargs):
        """
        Set value in SSSD config file. Parameter 'section' has to be specified.

        :param key:
        :param value:
        :param args:
        :param kwargs:
        :return:
        """
