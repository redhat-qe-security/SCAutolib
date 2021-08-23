import time
from subprocess import check_output, PIPE
from SCAutolib import base_logger
from traceback import format_exc


class VirtCard:
    """
    Class that represents virtual smart card in the tests.
    The of the system level, smart card is represnted as a systemd service.
    Starting and stoping this service simulattes insertion and removing the card.

    This class can be used in context manage (with statment).
    """

    def __init__(self, username, insert=False):
        """
        Constructor for virtual smart card.

        Args:
            insert: specify if virtual smart card should be automatically
                    inserted in the context manager
        """
        self._insert = insert
        self.service_name = f"virt_cacard_{username}.service"
        base_logger.debug("Smart card initialized")

    def __enter__(self):
        if self._insert:
            self.insert()
        return self

    def __exit__(self, exp_type, exp_value, exp_traceback):
        if exp_type is not None:
            base_logger.error("Exception in virtual smart card context")
            base_logger.error(format_exc())
        self.remove()

    def remove(self):
        """Simulate removing of the smart card by stopping the systemd service."""
        check_output(["systemctl", "stop", self.service_name], stderr=PIPE, encoding='utf-8')
        time.sleep(2)
        base_logger.debug("Smart card removed")

    def insert(self):
        """Simulate inserting of the smart card by starting the systemd service."""
        check_output(["systemctl", "start", self.service_name], stderr=PIPE, encoding='utf-8')
        time.sleep(2)
        base_logger.debug("Smart card is inserted")

    def enroll(self):
        """Upload new certificates to the virtual smart card. TO BE DONE"""
        pass
