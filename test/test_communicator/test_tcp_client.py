"""Test TCP client behaviour when the PLC is unreachable."""
import socket
import threading
import time

import pytest

from ...communicator import tcp_client
from ...communicator.tcp_client import TcpClient
from ...helper.exceptions import ConnectionException


def _free_port() -> int:
    """Return a local TCP port with nothing listening on it."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_refused_connection_fails_fast_and_does_not_hold_lock():
    """Failed connection must not block callers (no sleep under the lock)."""
    client = TcpClient("127.0.0.1", _free_port(), 0)

    start = time.monotonic()
    with pytest.raises(ConnectionException):
        client.send_and_receive("message")
    assert time.monotonic() - start < 2
    assert client._sock is None  # pylint: disable=protected-access
    assert not client._lock.locked()  # pylint: disable=protected-access


def test_no_reconnect_attempt_during_backoff(monkeypatch):
    """After a failed attempt the next requests fail immediately."""
    attempts = []
    real_socket = socket.socket

    class CountingSocket(real_socket):
        """Socket counting connect attempts."""

        def connect(self, address):
            attempts.append(address)
            return super().connect(address)

    monkeypatch.setattr(tcp_client.socket, "socket", CountingSocket)
    client = TcpClient("127.0.0.1", _free_port(), 0)

    for _ in range(5):
        with pytest.raises(ConnectionException):
            client.send_and_receive("message")
    assert len(attempts) == 1


def test_reconnects_after_backoff(monkeypatch):
    """When the delay passed the client tries to connect again."""
    attempts = []
    real_socket = socket.socket

    class CountingSocket(real_socket):
        """Socket counting connect attempts."""

        def connect(self, address):
            attempts.append(address)
            return super().connect(address)

    monkeypatch.setattr(tcp_client.socket, "socket", CountingSocket)
    client = TcpClient("127.0.0.1", _free_port(), 0)

    with pytest.raises(ConnectionException):
        client.send_and_receive("message")
    client._retry_after = 0.0  # pylint: disable=protected-access
    with pytest.raises(ConnectionException):
        client.send_and_receive("message")
    assert len(attempts) == 2


def test_connection_closed_by_peer_drops_socket():
    """Closed connection must raise and reset the socket (no endless loop)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_and_close():
        conn, _ = server.accept()
        conn.recv(1024)
        conn.close()

    thread = threading.Thread(target=accept_and_close, daemon=True)
    thread.start()
    client = TcpClient("127.0.0.1", port, 0)
    try:
        with pytest.raises(ConnectionException):
            client.send_and_receive("message")
        assert client._sock is None  # pylint: disable=protected-access
    finally:
        thread.join(2)
        server.close()


def test_close_is_immediate():
    """Closing the client must not sleep."""
    client = TcpClient("127.0.0.1", _free_port(), 0)
    start = time.monotonic()
    client.close()
    assert time.monotonic() - start < 1
