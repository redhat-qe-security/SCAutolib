import yaml
from SCAutolib.src import set_config, LIB_CONF


def test_set_config():
    set_config("new_field", "10", type_=int)
    with open(LIB_CONF, "r") as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
    assert "new_field" in data.keys()
    assert data['new_field'] == 10
    assert type(data['new_field']) == int
