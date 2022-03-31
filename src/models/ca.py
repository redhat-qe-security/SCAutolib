from pathlib import Path


class CA:

    def request_cert(self, csr, username: str, cert_out: Path):
        """
        Request certificate from CA for given username

        :param csr: path to CSR
        :param username: subject for the certificate
        :param cert_out: path where the certificate should be duplicated.
                         Default None
        :return: None or path where the certificate is stored.
        """
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
