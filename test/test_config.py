import yaml
from SCAutolib import set_config, LIB_CONF, LIB_DIR
from pathlib import Path


def test_set_config():
    Path(LIB_DIR).mkdir(exist_ok=True, parents=True)
    set_config("new_field", "10", type_=int)
    with open(LIB_CONF, "r") as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
    assert "new_field" in data.keys()
    assert data['new_field'] == 10
    assert type(data['new_field']) == int
    Path(LIB_CONF).unlink()
