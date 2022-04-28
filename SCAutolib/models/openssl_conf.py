"""
This module provide information and methods to create and modify
openssl cnf file. Following methods are implemented:

create: create content of internal file object representing openssl cnf file
save:  save content of internal file object representing openssl cnf file to
       .cnf file specified by user
"""
from pathlib import Path
from typing import Union

from SCAutolib import TEMPLATES_DIR
from SCAutolib.models.file import File


class OpensslCnf(File):
    """
    This class contains information and methods to handle openssl cnf files
    """
    _template = None
    _conf_file = None
    _content = None
    _old_string = None
    _new_string = None

    # openssl cnf content depends substantially on its purpose and separate
    # templates are needed for specific config files types. mapping:
    types = {
        "CA": {"template": Path(TEMPLATES_DIR, 'ca.cnf'),
               "replace": "{ROOT_DIR}"},
        "user": {"template": Path(TEMPLATES_DIR, 'user.cnf'),
                 "replace": "{user}"}
    }

    def __init__(self, filepath: Union[str, Path], conf_type: str, replace: str):
        """
        Init of opensslCNF

        :param filepath: Path of config file
        :type filepath: str or pathlib.Path
        :param conf_type: Identifier of cnf file
        :type conf_type: basestring
        :param replace: string that will replace specific string from template
        :type replace: str
        """
        self._conf_file = Path(filepath)
        self._template = Path(self.types[conf_type]["template"])
        self._old_string = self.types[conf_type]["replace"]
        self._new_string = replace

    def create(self):
        """
        Populate internal file object with content based on template
        and update specific strings
        """
        with self._template.open('r') as template:
            template_content = template.read()
        self._content = template_content.replace(self._old_string, self._new_string)

    def save(self):
        """
        Save content stored in internal file object to config file.
        """
        with self._conf_file.open("w") as config:
            if self._default_parser is None:
                config.write(self._content)
            else:
                # in case set method was used
                self._default_parser.write(config)
