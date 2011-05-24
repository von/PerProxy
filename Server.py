"""Classes for connections to PerProxy client and server"""

import M2Crypto

from Perspectives import Fingerprint

class Server:
    """Connection to PerProxy server"""

    def __init__(self, hostname, port):
        """Connect to given hostname and port via SSL"""
        # We use M2Crypto.SSL.Connection here because it allows us to get
        # the server certificate without validating it (with the python
        # ssl module does not allow.
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
        self.sock.send(msg)

    def sendall(self, msg):
        self.sock.sendall(msg)

    def recvall(self, buflen=8192):
        """Given a non-blocking socket, read all panding data.

        Socket can be ssl.SSLSocket or M2Crypto.SSL.Connection."""
        chunks = []
        while True:
            try:
                # SSLSocket will raise ssl.SSLError if no data pending
                #           or return 0 bytes on EOF
                # M2Crypto.SSL.Connection will return None
                data = self.sock.recv(buflen)
            except ssl.SSLError:
                data = None
            if data is None or len(data) == 0:
                break
            chunks.append(data)
        return "".join(chunks)

    def __str__(self):
        return "server at {}:{}".format(self.hostname, self.port)
