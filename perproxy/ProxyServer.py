"""ProxyServer and Handler class"""

import logging

from OpenSSL import SSL
from twisted.internet import ssl
from twisted.internet.protocol import Factory
from twisted.protocols import basic
from twisted.web import http

from ProxyClient import ProxyConnector

######################################################################

class ProxyServerTLSContextFactory(ssl.DefaultOpenSSLContextFactory):
    def __init__(self, target_hostname):
        self.target_hostname = target_hostname
        # TODO: Check self.certificateAuthority != None
        cert_file, key_file = self.certificateAuthority.get_ssl_credentials(target_hostname)
        ssl.DefaultOpenSSLContextFactory.__init__(self,
                                                  privateKeyFileName=key_file,
                                                  certificateFileName=cert_file)

    @classmethod
    def setCertificateAuthority(cls, ca):
        """Set the CA to use for generating certificates for MITM connections"""
        cls.certificateAuthority = ca

######################################################################

class ProxyServer(basic.LineReceiver):

    def __init__(self):
        self.header = {}
        self.firstLine = True
        self.__header = None  # Last header line read to allow for
                              # multi-line headers
        self.logger = self.__getLogger()
        self.server = None   # ProxyClient instance

    __logger = None

    @classmethod
    def __getLogger(cls):
        """Return our logger instance"""
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger


    def breakConnection(self):
        """Break connection to client and server"""
        self.logger.debug("Breaking connection on client side")
        self.transport.loseConnection()
        self.server = None

    def connectionMade(self):
        """Handle connected client"""
        self.logger.debug("ProxyServer started")

    def connectionLost(self, reason):
        """Handle dropped connection"""
        self.logger.debug("Connection to client lost: %s" % reason.getErrorMessage())
        if self.server:
            self.server.breakConnection()
            self.server = None

    def lineReceived(self, line):
        """Parse command line and headers for request"""
        if self.firstLine:
            self.parseCommand(line)
        elif not line or line == '':
            # End of headers
            self.endOfHeaders()
            self.handleProxyCommand()
        else:
            self.parseHeader(line)

    def parseCommand(self, line):
        """Parse command line"""
        self.logger.debug("Parsing command: %s" % line)
        self.firstLine = False
        parts = line.split()
        if len(parts) != 3:
            self.respond(http.BAD_REQUEST)
            self.transport.loseConnection()
            return
        self.command, self.target, self.version = parts
        self.target_hostname, self.target_port = self.parseTarget(self.target)

    def handleProxyCommand(self):
        """Handle the command we've received from the client"""
        if self.command != "CONNECT":
            self.respond(http.BAD_REQUEST)
            self.transport.loseConnection()
            return
        else:
            self.connectToServer()
        
    def parseHeader(self, line):
        """Parse a header line"""
        if line[0] in " \t":
            # Continuation line
            if self.__header is None:
                self.logger.error("Got continuation line without prior line")
                self.respond(http.BAD_REQUEST)
                self.transport.loseConnection()
                return
            self.__header += "\n" + line
        else:
            if self.__header:
                # Parse prior header received
                self.headerReceived(self.__header)
            self.__header = line

    def headerReceived(self, header):
        """Parse complete header"""
        key, val = header.split(":", 1)
        key = key.lower()
        val = val.strip()
        self.header[key] = val

    def endOfHeaders(self):
        """All headers received"""
        # Parse any pending header
        if self.__header:
            self.headerReceived(self.__header)
            self.__header = None

    def rawDataReceived(self, data):
        self.logger.debug("Read %d bytes" % len(data))
        if self.server:
            self.server.transport.write(data)

    def respond(self, status, msg=None):
        if msg is None:
            try:
                msg = http.RESPONSES[status]
            except IndexError:
                msg = ""
        self.logger.debug("Responding: %d %s" % (status, msg))
        self.transport.write("HTTP/1.1 %d %s\r\n\r\n" % (status, msg))

    def connectToServer(self):
        """Start connection to server"""
        # TODO: Pass headers along to server?
        self.logger.debug("Creating connection to %s" % self.target)
        ProxyConnector.connectToServer(self, self.target)
        return

    def serverConnectionEstablished(self, server):
        """Called with connection to server successfully established."""
        self.logger.debug("Connection to server made")
        self.server = server
        self.logger.debug("Responding to client and starting TLS")
        self.respond(http.OK)
        self.setRawMode()
        # All data will be processed by rawDataReceived() from now on
        self.startTLS()
        # Now we just pass opaque data

    def startTLS(self):
        """Start TLS with client"""
        ctxFactory = ProxyServerTLSContextFactory(self.target_hostname)
        self.transport.startTLS(ctxFactory, ProxyServerFactory())

    @classmethod
    def parseTarget(cls, target, defaultPort = 443):
        """Parse target, returning host and port"""
        if ":" in target:
            host, port = target.split(":")
            port = int(port)
        else:
            host = target
            port = defaultPort
        return host, port

######################################################################

class ProxyServerFactory(Factory):
    __logger = None

    @classmethod
    def __getLogger(cls):
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger

    def startFactory(self):
        logger = self.__getLogger()
        logger.debug("ProxyServerFactory started")

    def stopFactory(self):
        logger = self.__getLogger()
        logger.debug("ProxyServerFactory stopped")

    protocol = ProxyServer 
    
    def buildProtocol(self, addr):
        logger = self.__getLogger()
        logger.info("Got conection from %s:%d" % (addr.host, addr.port))
        return self.protocol()
