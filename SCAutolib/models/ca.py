from pathlib import Path


class CA:

    def request_cert(self, csr, username: str, cert_out: Path):
        """
        Request certificate from CA for given username

        :param csr: path to CSR
        :type csr: str
        :param username: subject for the certificate
        :type username: str
        :param cert_out: path where the certificate should be duplicated.
            Default None
        :type cert_out: pathlib.Path
        :return: None or path where the certificate is stored.
        """
        ...

    def setup(self, force: bool = False):
        """
        Configure the CA

        :param force: In case if CA is already configured, specifies if it
            should be reconfigured with force
        :type force: bool
        """
        ...

    def sign_cert(self):
        """
        Sign the certificate
        """
        ...

    def revoke_cert(self, cert: Path):
        """
        Revoke the certificate

        :param cert:
        :type cert: pathlib.Path
        """
        ...
