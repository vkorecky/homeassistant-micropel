"""TCP client."""
import logging
import socket
import threading
import time
from typing import Optional

from ..helper.crypto import Crypto
from ..helper.exceptions import ExceptionResponse, MicropelException
from ..helper.message import Message

_LOGGER = logging.getLogger(__name__)


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

    def send_and_receive(self, message: str) -> Optional[str]:
        """Send and receive data from server."""
        with self._lock:
            try:
                sock = self.getSocket()
                if sock is not None:
                    request = self._cryptography.code_string(message)
                    request += "\r"
                    wait = True
                    sock.sendall(request.encode("utf-8"))
                    while wait:
                        response = sock.recv(1024)
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
                _LOGGER.error("Cannot send message to %s port %s: %s", self._host, self._port, e)
                self._sock = None
        return None

    def getSocket(self):
        if not is_socket_connected(self._sock):
            self.connect()
        return self._sock

    def reconnect(self):
        self.close()
        return self.connect()

    def connect(self):
        """Connect to server."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _LOGGER.debug("Connecting to %s port %s", self._host, self._port)
            self._sock.settimeout(20)
            self._sock.connect((self._host, self._port))
        except OSError as e:
            self.close()
        return None

    def close(self):
        """Close connection with server."""
        _LOGGER.debug("Closing socket")
        if self._sock is not None:
            self._sock.close()
            sock = None
            time.sleep(5)


def is_socket_connected(sock: socket):
    if sock is None:
        return False
    try:
        sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)
        return True
    except OSError:
        return False
