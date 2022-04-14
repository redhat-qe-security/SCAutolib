"""
Exceptions that are used in the SCAutolib
"""


class SCAutolibException(Exception):
    """
    Base SCAutolib exception
    """
    def __init__(self, *args):
        super().__init__(*args)
