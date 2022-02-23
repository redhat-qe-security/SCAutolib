from pathlib import Path

from .ca import BaseCA


class IPAServer(BaseCA):

    def request_cert(self, csr: Path, username: str):
        """Request certificate from the IPA server for given username"""
