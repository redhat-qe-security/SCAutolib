from pathlib import Path


class CA:

    def request_cert(self, csr, username: str):
        """Request certificate from CA for given username"""
        ...

    def setup(self, force: bool = False):
        """
        Configure the CA
        :param force: In case if CA is already configured, specifies if it
                      should be reconfigured with force
        :return:
        """
        ...

    def sign_cert(self):
        ...

    def revoke_cert(self, cert: Path):
        ...
