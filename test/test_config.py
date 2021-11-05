import yaml
from SCAutolib.src import set_config
from SCAutolib.test.fixtures import *  # noqa: F401


def test_set_config(loaded_env):
    _, conf = loaded_env
    set_config("new_field", "10", type_=int)
    with open(conf, "r") as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
    assert "new_field" in data.keys()
    assert data['new_field'] == 10
    assert type(data['new_field']) == int
