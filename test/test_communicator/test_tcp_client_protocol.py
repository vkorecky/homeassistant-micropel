"""Tests of the TCP client against a fake CA5 (encryption, replies, reconnect)."""
import socket
import time

import pytest

from ...communicator import tcp_client
from ...communicator.tcp_client import TcpClient, is_socket_connected
from ...helper.exceptions import (
    ConnectionException,
    ExceptionResponse,
    MicropelException,
)
from ...helper.message import Message
from .fake_ca5 import CLOSE, FakeCa5, frame

PASSWORD = 468945
READ_D40 = Message.build_message(1, "*", 0x2E, "000000D081")
READ_REPLY = frame("@01*2E000000D0810AA7")


@pytest.fixture(autouse=True)
def short_timeouts(monkeypatch):
    """Keep the tests fast."""
    monkeypatch.setattr(tcp_client, "IO_TIMEOUT", 1.0)
    monkeypatch.setattr(tcp_client, "CONNECT_TIMEOUT", 1.0)


@pytest.fixture(name="ca5")
def ca5_fixture():
    """Fake CA5 answering every request with the value of D40."""
    server = FakeCa5(PASSWORD, lambda request, number: READ_REPLY)
    yield server
    server.close()


def _client(server, password=PASSWORD):
    client = TcpClient("127.0.0.1", server.port, password)
    client.connect()
    return client


def test_request_and_reply_are_encrypted(ca5):
    """The reply is decoded and the data returned."""
    client = _client(ca5)
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    assert ca5.requests == [READ_D40]
    client.close()


def test_more_requests_on_one_connection(ca5):
    """The cipher state is reset by the CR, so every request is understood."""
    client = _client(ca5)
    for _ in range(4):
        assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    assert ca5.requests == [READ_D40] * 4
    assert ca5.connections == 1
    client.close()


def test_without_password_nothing_is_encrypted():
    """Password 0 means plain text."""
    server = FakeCa5(0, lambda request, number: READ_REPLY)
    client = _client(server, 0)
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    assert server.requests == [READ_D40]
    client.close()
    server.close()


def test_async_frame_is_skipped():
    """Frames with the command 6E are not replies, the real reply follows."""
    server = FakeCa5(
        PASSWORD, lambda request, number: [frame("@01*6E00"), 0.2, READ_REPLY]
    )
    client = _client(server)
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    client.close()
    server.close()


def test_error_response_is_raised_and_logged(caplog):
    """A reply of type '!' raises ExceptionResponse with the reply in it."""
    server = FakeCa5(PASSWORD, lambda request, number: frame("@01!2E02"))
    client = _client(server)
    with pytest.raises(ExceptionResponse) as err:
        client.send_and_receive(READ_D40)
    assert "@01!2E02" in str(err.value)
    assert "PLC answered with an error" in caplog.text
    client.close()
    server.close()


def test_reply_without_command_marker_is_logged(caplog):
    """A reply decoded with a wrong password is reported with the raw data."""
    server = FakeCa5(PASSWORD, lambda request, number: frame("@01*2E0000"))
    client = _client(server, 1234)  # wrong password of the client
    with pytest.raises(MicropelException):
        client.send_and_receive(READ_D40)
    assert "Unexpected reply" in caplog.text
    client.close()
    server.close()


def test_too_short_reply_is_a_protocol_error():
    """A reply shorter than a message raises MicropelException."""
    server = FakeCa5(0, lambda request, number: "*2E")
    client = _client(server, 0)
    with pytest.raises(MicropelException):
        client.send_and_receive(READ_D40)
    client.close()
    server.close()


def test_idle_connection_closed_by_ca5_is_reopened():
    """After the CA5 closed the idle connection the request is repeated."""
    server = FakeCa5(PASSWORD, lambda request, number: READ_REPLY, idle_timeout=0.3)
    client = _client(server)
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    time.sleep(0.8)  # the CA5 closes the connection
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    assert server.connections == 2
    client.close()
    server.close()


def test_connection_closed_twice_raises():
    """When the reconnect does not help, the error is raised."""
    server = FakeCa5(PASSWORD, lambda request, number: CLOSE)
    client = _client(server)
    with pytest.raises(ConnectionException):
        client.send_and_receive(READ_D40)
    assert client._sock is None  # pylint: disable=protected-access
    client.close()
    server.close()


def test_reopen_fails_when_ca5_refuses():
    """When the CA5 does not accept a new connection, the request fails."""
    server = FakeCa5(PASSWORD, lambda request, number: CLOSE)
    client = _client(server)
    server.close()  # nobody listens any more
    with pytest.raises(ConnectionException) as err:
        client.send_and_receive(READ_D40)
    assert "Not connected" in str(err.value)
    client.close()


def test_reopen_pauses_between_attempts(monkeypatch):
    """_reopen() tries several times with a pause."""
    sleeps = []
    monkeypatch.setattr(tcp_client.time, "sleep", sleeps.append)
    client = TcpClient("127.0.0.1", 1, 0)
    monkeypatch.setattr(client, "connect", lambda: None)
    assert client._reopen(attempts=3, pause=0.5) is False  # pylint: disable=protected-access
    assert sleeps == [0.5, 0.5]


def test_reconnect_opens_a_new_connection(ca5):
    """reconnect() closes the old connection and opens a new one."""
    client = _client(ca5)
    client.reconnect()
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    assert ca5.connections == 2
    client.close()


def test_get_socket_connects_when_needed(ca5):
    """getSocket() opens the connection on demand."""
    client = TcpClient("127.0.0.1", ca5.port, PASSWORD)
    assert client._sock is None  # pylint: disable=protected-access
    assert client.getSocket() is not None
    client.close()


def test_connect_resets_the_cipher_state(ca5):
    """Every new connection starts with a fresh cipher."""
    client = _client(ca5)
    client._cryptography.code_string("abc")  # pylint: disable=protected-access
    client.reconnect()
    assert client.send_and_receive(READ_D40) == "000000D0810AA7"
    client.close()


def test_is_socket_connected():
    """is_socket_connected() handles None and closed sockets."""
    assert is_socket_connected(None) is False
    sock = socket.socket()
    sock.close()
    assert is_socket_connected(sock) is False


def test_close_ignores_errors():
    """close() never raises."""
    client = TcpClient("127.0.0.1", 1, 0)

    class BrokenSocket:
        """Socket which fails on close."""

        def close(self):
            """Raise like a broken socket."""
            raise OSError("broken")

    client._sock = BrokenSocket()  # pylint: disable=protected-access
    client.close()
    assert client._sock is None  # pylint: disable=protected-access
