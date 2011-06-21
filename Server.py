"""Server: class wrapping connection to target HTTPS server from PerProxy"""

import logging
import ssl

import M2Crypto

from Perspectives import Fingerprint

class Server:
    """Connection to target HTTPS server"""

    def __init__(self, hostname, port):
        """Connect to given hostname and port via SSL"""
        self.logger = logging.LoggerAdapter(
            logging.getLogger(self.__class__.__name__),
            { "target" : hostname })
        # We use M2Crypto.SSL.Connection here because it allows us to get
        # the server certificate without validating it (which the python
        # ssl module does not allow).
        self.context = M2Crypto.SSL.Context("sslv3")
        self.sock = M2Crypto.SSL.Connection(self.context)
        self.sock.connect((hostname, port))
        self.hostname = hostname
        self.port = port

    def make_nonblocking(self):
        self.sock.setblocking(False)

    def get_cert(self):
        """Return M2Crypto.X509.X509 certificate of server"""
        return self.sock.get_peer_cert()

    def get_fingerprint(self):
        """Return the Fingerprint of ther server"""
        return Fingerprint.from_M2Crypto_X509(self.get_cert())

    def subject(self):
        """Return M2Crypto.X509.X509Name of server"""
        return self.get_cert().get_subject()

    def close(self):
        self.sock.close()
        # XXX Need to clean up self.context?

    def send(self, msg):
        try:
            self.sock.send(msg)
        except IOError as e:
            self.logger.warn("Error sending to {}: {}".format(self.hostname,
                                                              str(e)))

    def sendall(self, msg):
        try:
            self.sock.sendall(msg)
        except IOError as e:
            self.logger.warn("Error sending to {}: {}".format(self.hostname,
                                                              str(e)))

    def recvall(self, buflen=8192):
        """Read all panding data.

        On EOF, returns a 0-length string.

        M2Crypto.SSL.Connection seems to randomly return None
        sometimes after claiming it has data to read. This does not indicate
        EOF. In this case, this function will return None and the caller
        should not treat as an EOF."""
        chunks = []
        while True:
            try:
                data = self.sock.recv(buflen)
            except Exception as e:
                self.logger.warning("Got error reading: {}".format(str(e)))
                return ""  # Treat as EOF
            # I think len(data) == 0 means EOF and data == None is meaningless.
            if data is None:
                break
            if len(data) == 0:
                break
            chunks.append(data)
        if data is None and len(chunks) == 0:
            # Ignorable None read
            return None
        return "".join(chunks)

    def __str__(self):
        return "server at {}:{}".format(self.hostname, self.port)
