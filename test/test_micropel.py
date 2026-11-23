"""Tests of the Micropel hub (the part of the integration which owns the connection)."""
import time
from unittest.mock import MagicMock

import pytest

from homeassistant.const import (
    CONF_COVERS,
    CONF_HOST,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_PORT,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.exceptions import HomeAssistantError

from .. import micropel as micropel_module
from ..communicator.mpc_300 import Mpc300
from ..communicator.mpc_400 import Mpc400
from ..const import (
    COMMUNICATOR_TYPE_MPC300,
    COMMUNICATOR_TYPE_MPC400,
    CONF_CLIMATES,
    CONF_COMMUNICATOR_TYPE,
    DOMAIN,
    SERVICE_WRITE_COIL,
    SERVICE_WRITE_REGISTER,
)
from ..micropel import MicropelHub, micropel_setup
from .test_communicator.fake_ca5 import FakeCa5, frame

PASSWORD = 468945


def _config(port, communicator_type=COMMUNICATOR_TYPE_MPC400, **extra):
    config = {
        CONF_NAME: "ca5",
        CONF_HOST: "127.0.0.1",
        CONF_PORT: port,
        CONF_PASSWORD: PASSWORD,
        CONF_COMMUNICATOR_TYPE: communicator_type,
    }
    config.update(extra)
    return config


def _responder(request, number):
    """Answer like the PLC: reads return the value, writes confirm it."""
    if request.startswith("@01*2E000000D0"):
        return frame("@01*2E000000D0810AA7")
    if request.startswith("@01*2F000000D0"):
        return frame("@01*2F000000D0810BB8")
    if request.startswith("@01*2E00000210"):
        return frame("@01*2E0000021001")
    return frame("@01*2F0000021001")


@pytest.fixture(name="ca5")
def ca5_fixture():
    """Fake CA5 which understands the requests used in the tests."""
    server = FakeCa5(PASSWORD, _responder)
    yield server
    server.close()


def test_hub_selects_the_communicator():
    """The type of the communicator decides the protocol."""
    hub300 = MicropelHub(_config(1, COMMUNICATOR_TYPE_MPC300))
    hub400 = MicropelHub(_config(1, COMMUNICATOR_TYPE_MPC400))
    assert isinstance(hub300._communicator, Mpc300)  # pylint: disable=protected-access
    assert isinstance(hub400._communicator, Mpc400)  # pylint: disable=protected-access
    assert hub400.name == "ca5"


def test_hub_refuses_unknown_communicator():
    """An unknown type of the communicator is a configuration error."""
    with pytest.raises(HomeAssistantError):
        MicropelHub(_config(1, "MPC999"))


def test_hub_reads_and_writes(ca5):
    """The hub passes the requests to the PLC and returns the values."""
    hub = MicropelHub(_config(ca5.port))
    hub.setup()
    assert hub.read_word(1, 0xD0) == "0x0AA7"
    assert hub.write_word(1, 0xD0, 3000) == "0x0BB8"
    assert hub.read_bit(1, 0x210, 0) is True
    assert hub.write_bit(1, 0x210, 0, True) is True
    hub.close()


def test_hub_connect_and_close(ca5):
    """connect() opens and close() closes the connection."""
    hub = MicropelHub(_config(ca5.port))
    hub.connect()
    assert hub.read_word(1, 0xD0) == "0x0AA7"
    hub.close()
    assert ca5.connections == 1


@pytest.fixture(name="load_platform")
def load_platform_fixture(monkeypatch):
    """Replace load_platform of Home Assistant."""
    mock = MagicMock()
    monkeypatch.setattr(micropel_module, "load_platform", mock)
    return mock


def _setup(config_hub):
    hass = MagicMock()
    hass.data = {}
    config = {DOMAIN: [config_hub]}
    assert micropel_setup(hass, config, MagicMock(), MagicMock()) is True
    return hass, config


def test_setup_creates_the_hub_and_registers_services(ca5, load_platform):
    """The setup connects the hub, registers the services and the stop handler."""
    hass, _ = _setup(_config(ca5.port))
    assert "ca5" in hass.data[DOMAIN]
    for _ in range(50):  # the server counts the connection in its own thread
        if ca5.connections:
            break
        time.sleep(0.05)
    assert ca5.connections == 1
    services = {call.args[1] for call in hass.services.register.call_args_list}
    assert services == {SERVICE_WRITE_REGISTER, SERVICE_WRITE_COIL}
    load_platform.assert_not_called()
    hass.bus.async_listen_once.assert_called_once()
    assert hass.bus.async_listen_once.call_args.args[0] == EVENT_HOMEASSISTANT_STOP


def test_setup_loads_climate_and_cover_platforms(ca5, load_platform):
    """The platforms configured in the hub block are loaded."""
    hub_config = _config(ca5.port, **{CONF_CLIMATES: [{}], CONF_COVERS: [{}]})
    _setup(hub_config)
    loaded = {call.args[1] for call in load_platform.call_args_list}
    assert loaded == {"climate", "cover"}


def test_stop_handler_closes_the_hubs(ca5, load_platform):
    """On the Home Assistant stop the connections are closed."""
    del load_platform
    hass, _ = _setup(_config(ca5.port))
    hub = hass.data[DOMAIN]["ca5"]
    hub.close = MagicMock()
    stop = hass.bus.async_listen_once.call_args.args[1]
    stop(None)
    hub.close.assert_called_once()
