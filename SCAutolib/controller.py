from .models import user


class Controller:

    def setup_user(self, *args, **kwargs):
        """Some documentation"""
        u = None
        username = kwargs["username"]
        password = kwargs["password"]

        if kwargs["type_"] == user.UserType.IPA_USER:
            u = user.IPAUser(username, password)
        elif kwargs["type_"] == user.UserType.LOCAL_USER:
            u = user.LocalUser(username, password)
        u.add_user()

    def create_card(self, *args, **kwargs):
        ...
