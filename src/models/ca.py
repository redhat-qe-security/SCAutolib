class BaseCA:

    def request_cert(self, csr, username: str): ...

    def json_store(self):
        """Store current CA configuration to JSON file"""

    def json_load(self):
        """Load CA configuration from JSON file"""
