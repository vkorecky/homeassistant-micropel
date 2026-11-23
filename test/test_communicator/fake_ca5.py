"""A tiny fake CA5 communicator (TCP server) for the communicator tests."""
import socket
import threading
import time

from ...helper.crc import CRC
from ...helper.crypto import Crypto

CLOSE = object()  # a responder returns this to close the connection


def frame(text: str) -> str:
    """Add the CRC to the text of a message."""
    return text + "#" + CRC.get_crc_sum(text)


class FakeCa5:
    """TCP server which decodes the requests and answers like a CA5 would.

    ``responder(request, connection_number)`` gets the decoded request (without
    CR) and returns None (no answer), CLOSE, a string or a list of strings
    (frames, the CR is added and they are encoded with the password). A number
    in the list is a pause in seconds between two frames.
    """

    def __init__(self, password=0, responder=None, idle_timeout=None):
        """Start the server on a free local port."""
        self.password = password
        self.responder = responder or (lambda request, number: None)
        self.idle_timeout = idle_timeout
        self.requests = []
        self.connections = 0
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(5)
        self.port = self._server.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def close(self):
        """Stop accepting connections."""
        self._server.close()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(
                target=self._handle, args=(conn, self.connections), daemon=True
            ).start()

    def _handle(self, conn, number):
        crypto = Crypto()
        crypto.crypt_init(self.password)
        conn.settimeout(self.idle_timeout)
        buffer = ""
        with conn:
            while True:
                try:
                    data = conn.recv(1024)
                except OSError:  # includes the idle timeout
                    return
                if not data:
                    return
                buffer += crypto.decode_string(data.decode("ascii"))
                while "\r" in buffer:
                    request, buffer = buffer.split("\r", 1)
                    self.requests.append(request)
                    reply = self.responder(request, number)
                    if reply is CLOSE:
                        return
                    if reply is None:
                        continue
                    for text in [reply] if isinstance(reply, str) else reply:
                        if isinstance(text, (int, float)):  # a pause between frames
                            time.sleep(text)
                            continue
                        conn.sendall(crypto.code_string(text + "\r").encode("ascii"))
