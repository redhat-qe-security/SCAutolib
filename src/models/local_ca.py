from .ca import BaseCA


class LocalCA(BaseCA):

    def request_cert(self, csr, username: str):
        """Request certificate from local CA for given username"""
