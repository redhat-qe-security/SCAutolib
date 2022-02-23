from pathlib import Path


class Card:
    softhsm2_conf: Path = None
    service_name: str = None

    def insert(self): ...

    def remove(self): ...

    def upload_cert(self): ...
