"""Tests of the MPC300/MPC400 communicators (messages and parsing of replies)."""
import pytest

from ...communicator.abstract_communicator import AbstractCommunicator
from ...communicator.mpc_300 import Mpc300
from ...communicator.mpc_400 import Mpc400
from ...helper.crc import CRC


class FakeTcpClient:
    """Records the sent messages and returns the prepared reply data."""

    def __init__(self, reply=None):
        """Initialize the fake."""
        self.reply = reply
        self.sent = []
        self.connected = False
        self.closed = False

    def send_and_receive(self, message):
        """Remember the message and return the reply."""
        self.sent.append(message)
        return self.reply

    def connect(self):
        """Remember the call."""
        self.connected = True

    def close(self):
        """Remember the call."""
        self.closed = True


def _communicator(cls, reply=None):
    communicator = cls("127.0.0.1", 10001, 0)
    communicator._tcp_client = FakeTcpClient(reply)  # pylint: disable=protected-access
    return communicator, communicator._tcp_client  # pylint: disable=protected-access


def _with_crc(body):
    return body + "#" + CRC.get_crc_sum(body)


def test_abstract_communicator_delegates_and_has_empty_interface():
    """connect() and close() go to the TCP client, the rest is only interface."""
    communicator, client = _communicator(AbstractCommunicator)
    communicator.connect()
    communicator.close()
    assert client.connected and client.closed
    assert communicator.read_word(1, 2) is None
    assert communicator.write_word(1, 2, 3) is None
    assert communicator.read_bit(1, 2, 3) is None
    assert communicator.write_bit(1, 2, 3, True) is None


def test_mpc400_read_word():
    """Word is read with 0x2E and the last 4 characters are the value."""
    communicator, client = _communicator(Mpc400, "000000D0810AA7")
    assert communicator.read_word(1, 0xD0) == "0x0AA7"
    assert client.sent == ["@01*2E000000D081#3F"]


def test_mpc400_write_word():
    """Word is written with 0x2F and the confirmed value is returned."""
    communicator, client = _communicator(Mpc400, "000000D0810AA7")
    assert communicator.write_word(1, 0xD0, 0x0AA7) == "0x0AA7"
    assert client.sent == [_with_crc("@01*2F000000D0810AA7")]


def test_mpc400_read_bit():
    """Bit is read with 0x2E, the last two characters tell the state."""
    communicator, client = _communicator(Mpc400, "0000021001")
    assert communicator.read_bit(1, 0x210, 0) is True
    assert client.sent == [_with_crc("@01*2E0000021000")]
    client.reply = "0000021000"
    assert communicator.read_bit(1, 0x210, 0) is False


@pytest.mark.parametrize("value, control", [(True, 0x0B), (False, 0x03)])
def test_mpc400_write_bit(value, control):
    """Bit is written with 0x2F, the value is the bit 3 of the control byte."""
    communicator, client = _communicator(Mpc400, "0000021001")
    assert communicator.write_bit(1, 0x210, 3, value) is True
    assert client.sent == [_with_crc(f"@01*2F00000210{control:02X}")]


def test_mpc300_read_word():
    """MPC300 reads the word with 0x44 and a 4 digit address."""
    communicator, client = _communicator(Mpc300, "00D00AA7")
    assert communicator.read_word(3, 0xD0) == "0x0AA7"
    assert client.sent == [_with_crc("@03*4400D0")]


def test_mpc300_write_word():
    """MPC300 writes the word with 0x45."""
    communicator, client = _communicator(Mpc300, "00D00AA7")
    assert communicator.write_word(3, 0xD0, 0x0AA7) == "0x0AA7"
    assert client.sent == [_with_crc("@03*4500D00AA7")]


def test_mpc300_read_bit():
    """MPC300 reads the bit with 0x2A and a mask of the bit."""
    communicator, client = _communicator(Mpc300, "054901")
    assert communicator.read_bit(3, 0x549, 2) is True
    assert client.sent == [_with_crc("@03*2A054904")]
    client.reply = "054900"
    assert communicator.read_bit(3, 0x549, 2) is False


@pytest.mark.parametrize("value, flag", [(True, "01"), (False, "00")])
def test_mpc300_write_bit(value, flag):
    """MPC300 writes the bit with 0x2B, the mask and the value."""
    communicator, client = _communicator(Mpc300, "054901")
    assert communicator.write_bit(3, 0x549, 7, value) is True
    assert client.sent == [_with_crc(f"@03*2B054980{flag}")]
