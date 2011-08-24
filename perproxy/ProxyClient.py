"""Implementation of twisted ProxyClient protocol"""
import logging

from OpenSSL import SSL
from twisted.internet import reactor, ssl
from twisted.internet.protocol import ClientFactory, Protocol
from twisted.internet.ssl import Certificate

######################################################################
#
# Utility functions
#

class ProxyConnector:
    """Handle making a connection between a ProxyServer and ProxyClient"""

    __logger = None

    @classmethod
    def __getLogger(cls):
        """Return our logger instance"""
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger
    
    @classmethod
    def connectToServer(cls, client, conf, target):
        """Make connection to server at target from client

        client must be a ProxyServer instance
        conf must be a Configuration insance
        target is a string of the form: hostname[:port]"""
        logger = cls.__getLogger()
        host, port = cls.parseTarget(target)
        logger.info("Creating connection to server: %s port %d" % (host, port))
        factory = ProxyClientFactory(client, conf, target)
        ctxFactory = ProxyClientTLSContextFactory()
        reactor.connectSSL(host, port, factory, ctxFactory)

    @classmethod
    def parseTarget(cls, target, defaultPort = 443):
        """Parse target, returning host and port"""
        if ":" in target:
            host, port = target.split(":")
            port = int(port)
        else:
            port = defaultPort
        return host, port

######################################################################

class ProxyClientTLSContextFactory(ssl.ClientContextFactory):
    isClient = 1

    __logger = None

    @classmethod
    def __getLogger(cls):
        """Return our logger instance"""
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger

    def getContext(self):
        logger = self.__getLogger()
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        def _verifyCallback(conn, cert, errno, depth, preverify_ok):
            return preverify_ok
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, _verifyCallback)
        def _infoCallback(conn, where, ret):
            # conn is OpenSSL.SSL.Connection
            # See http://www.openssl.org/docs/ssl/SSL_CTX_set_info_callback.html
            logger.debug("infoCallback %s %d %d" % (conn, where, ret))
            if where & SSL.SSL_CB_HANDSHAKE_START:
                logger.debug("Handshake started")
            if where & SSL.SSL_CB_HANDSHAKE_DONE:
                logger.debug("Handshake done")
            pass
        ctx.set_info_callback(_infoCallback)
        ctx.set_verify_depth(0)
        return ctx

######################################################################

class ProxyClient(Protocol):

    def __init__(self, client, conf, target):
        self.client = client
        self.conf = conf
        self.target = target
        self.logger = self.__getLogger()

    __logger = None

    @classmethod
    def __getLogger(cls):
        """Return our logger instance"""
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger

    def connectionMade(self):
        """Handle completed connection"""
        # Note, this doesn't mean the TLS handshake has been completed.
        # Attempts to get the peer certificate here will fail.
        self.logger.debug("Connection to %s made" % self.target)
        # DEBUG - should be SSL.Connection instance
        #self.logger.debug("Handle: %s" % self.transport.protocol.getHandle())
        self.checkServer()
        self.client.serverConnectionEstablished(self)

    def checkServer(self):
        """Check server with Perspectives"""
        if self.conf["WhiteList"]:
            if self.conf["WhiteList"].contains(self.target):
                self.logger.debug("Server %s whitelisted." % self.target)
                return
        if self.conf["Checker"] is None:
            pass  # XXX Throw error
        #cert = self.getServerCertificate()
        # DEBUG starts here
        #self.logger.info("Server subject is %s" % str(cert.getSubject()))

    def dataReceived(self, data):
        """Handle data received from server"""
        self.logger.debug("Read %d bytes from %s" % (len(data), self.target))
        if self.client:
            self.client.transport.write(data)

    def connectionLost(self, reason):
        """Handle a dropped connection"""
        self.logger.debug("Connection to server lost: %s" % reason.getErrorMessage())
        if self.client:
            self.client.breakConnection()
            self.client = None

    def breakConnection(self):
        """Break connection to server"""
        self.logger.debug("Breaking connection to server")
        self.transport.loseConnection()
        self.client = None

    def getServerCertificate(self):
        """Return the twisted.internet.ssl.Certificate instance for the server"""
        return Certificate.peerFromTransport(self.transport)

######################################################################

class ProxyClientFactory(ClientFactory):
    
    protocol = ProxyClient

    def __init__(self, client, conf, target):
        self.client = client
        self.conf = conf
        self.target = target
        self.logger = self.__getLogger()

    __logger = None

    @classmethod
    def __getLogger(cls):
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger

    def startedConnecting(self, connector):
        self.logger.debug("Starting connection to %s" % self.target)

    def buildProtocol(self, addr):
        return self.protocol(self.client, self.conf, self.target)

    def clientConnectionLost(self, connector, reason):
        self.logger.info("Lost connection to server: %s" % reason.getErrorMessage())

    def clientConnectionFailed(self, connector, reason):
        self.logger.info("Connection to %s failed. Reason: %s" % (self.target,
                                                                  reason))
        self.client.serverConnectionFailed(reason)
