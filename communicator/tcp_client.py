"""TCP client."""
import logging
import socket
import threading
import time
from typing import Optional

from ..helper.crypto import Crypto
from ..helper.exceptions import (
    ConnectionException,
    ExceptionResponse,
    MicropelException,
)
from ..helper.message import Message

_LOGGER = logging.getLogger(__name__)

# Timeout of establishing the TCP connection (seconds).
CONNECT_TIMEOUT = 3
# Timeout of sending/receiving data on an established connection (seconds).
IO_TIMEOUT = 10
# After a failed connection attempt do not try again for this time (seconds).
# While waiting, requests fail immediately instead of blocking the shared lock.
RECONNECT_DELAY = 30


class TcpClient:
    """TCP client."""

    def __init__(self, host: str, port: int, password: int):
        """TCP client constructor."""

        self._lock = threading.Lock()
        self._host = host
        self._port = port
        self._password = password
        self._cryptography = Crypto()
        self._cryptography.crypt_init(password)
        self._sock = None
        self._retry_after = 0.0

    def send_and_receive(self, message: str) -> Optional[str]:
        """Send and receive data from server.

        Raises ConnectionException when the PLC cannot be reached.
        """
        with self._lock:
            try:
                sock = self.getSocket()
                if sock is None:
                    raise ConnectionException(
                        f"Not connected to {self._host} port {self._port}"
                    )
                request = self._cryptography.code_string(message)
                request += "\r"
                wait = True
                sock.sendall(request.encode("utf-8"))
                while wait:
                    response = sock.recv(1024)
                    if not response:
                        raise OSError("Connection closed by the remote host")
                    response_str = response.decode("utf-8")
                    response_str = self._cryptography.decode_string(response_str)
                    cmd_id = Message.get_cmd_id(response_str)
                    if cmd_id != "6E":
                        wait = False
                if Message.is_valid_message(response_str):
                    raise MicropelException
                if Message.get_cmd_type(response_str) == "!":
                    raise ExceptionResponse
                data = Message.get_data(response_str)
                return data
            except OSError as e:
                _LOGGER.error(
                    "Cannot send message to %s port %s: %s", self._host, self._port, e
                )
                self.close()
                raise ConnectionException(
                    f"Communication with {self._host} port {self._port} failed: {e}"
                ) from e

    def getSocket(self):
        if not is_socket_connected(self._sock):
            self.connect()
        return self._sock

    def reconnect(self):
        self.close()
        return self.connect()

    def connect(self):
        """Connect to server."""
        now = time.monotonic()
        if now < self._retry_after:
            # A recent attempt failed, do not block the callers again.
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _LOGGER.debug("Connecting to %s port %s", self._host, self._port)
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((self._host, self._port))
            sock.settimeout(IO_TIMEOUT)
        except OSError as e:
            _LOGGER.error(
                "Cannot connect to %s port %s: %s (next attempt in %s s)",
                self._host,
                self._port,
                e,
                RECONNECT_DELAY,
            )
            sock.close()
            self._sock = None
            self._retry_after = now + RECONNECT_DELAY
            return None
        self._sock = sock
        self._retry_after = 0.0
        return None

    def close(self):
        """Close connection with server."""
        _LOGGER.debug("Closing socket")
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def is_socket_connected(sock: socket):
    if sock is None:
        return False
    try:
        sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)
        return True
    except OSError:
        return False
