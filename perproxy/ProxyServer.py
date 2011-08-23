"""ProxyServer class: Handles connection to client"""

import logging
import string

from OpenSSL import SSL
from twisted.internet import ssl
from twisted.internet.protocol import Factory
from twisted.protocols import basic
from twisted.web import http

from ProxyClient import ProxyConnector

######################################################################

class ProxyServerTLSContextFactory(ssl.DefaultOpenSSLContextFactory):
    def __init__(self, ca, target_hostname):
        cert_file, key_file = ca.get_ssl_credentials(target_hostname)
        ssl.DefaultOpenSSLContextFactory.__init__(self,
                                                  privateKeyFileName=key_file,
                                                  certificateFileName=cert_file)

######################################################################

class ProxyServer(basic.LineReceiver):

    _error_template = "SERVER ERROR: ${error}"

    def __init__(self, conf):
        """conf must be a Configuration instance"""
        self.conf = conf
        self.header = {}
        self.firstLine = True
        self.__header = None  # Last header line read to allow for
                              # multi-line headers
        self._state = _ReadingCommandState
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
        self.logger.debug("Received line")
        self._state.lineReceived(self, line)

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
        self._state.rawDataReceived(self, data)

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
        ProxyConnector.connectToServer(self, self.conf, self.target)
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
        self._state = _PassThroughState

    def serverConnectionFailed(self, error):
        """Called when connection to server failed.

        Error should be Reason."""
        self.logger.info("Connection to server failed: %s" % str(error))
        self._server_error = error
        self.respond(http.OK)
        # All data will be processed by rawDataReceived() from now on
        self.startTLS()
        # Clear headers from original command as we'll be reading new
        # ones from intercepted request
        self.header = {}
        # Now we read request from client and respond with HTML error
        self._state = _ServerErrorReadRequestState

    def respondWithServerError(self):
        """Respond with HTML to client containing server error"""
        # TODO: Look at headers and see if client is expecting HTML
        #       And do what if it isn't?
        error_message = self._server_error.getErrorMessage()
        self.logger.debug("Responding with Server error: %s" % error_message)
        self.respond(http.BAD_GATEWAY)
        values = {
            "title" : error_message,
            "error" : error_message,
            }
        template = string.Template(self._error_template)
        html = template.substitute(values)
        self.transport.write(html)
        self.logger.debug("Error response sent.")
        self.transport.loseConnection()

    def startTLS(self):
        """Start TLS with client"""
        ctxFactory = ProxyServerTLSContextFactory(self.conf["CA"],
                                                  self.target_hostname)
        self.transport.startTLS(ctxFactory)

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

    def writeToServer(self, data):
        """Write data to server, if we have connection"""
        if self.server:
            self.server.transport.write(data)

    @classmethod
    def setErrorTemplate(cls, template):
        """Set error template for reporting errors to client"""
        cls._error_template = template

######################################################################

class ProxyServerFactory(Factory):
    __logger = None

    # List of allowed clients
    allowed_clients = [
        "127.0.0.1"  # Localhost
        ]

    def __init__(self, conf):
        """conf must be a Configuration instance"""
        self.conf = conf

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
        if addr.host not in self.allowed_clients:
            logger.error("Rejected connection from client at %s:%d" % (addr.host, addr.port))
            return None
        return self.protocol(self.conf)

######################################################################

class _State:
    """Base class for ProxyServer states"""

    @classmethod
    def lineReceived(cls, server, line):
        raise NotImplementedError("lineReceived() method not implemented for state")

    @classmethod
    def rawDataReceived(cls, server, data):
        raise NotImplementedError("rawDataReceived() method not implemented for state")

class _ReadingCommandState:
    """Reading first line which contains command"""

    @classmethod
    def lineReceived(cls, server, line):
        server.parseCommand(line)
        server._state = _ReadingHeaderState

class _ReadingHeaderState:
    """Reading header following command"""

    @classmethod
    def lineReceived(cls, server, line):
        if not line or line == '':
            server.endOfHeaders()
            server.connectToServer()
        else:
            server.parseHeader(line)

class _PassThroughState:
    """Just passing data between client and server"""
    @classmethod
    def rawDataReceived(cls, server, data):
        server.writeToServer(data)

class _ServerErrorReadRequestState:
    """Intercept request from client to server"""
    @classmethod
    def lineReceived(cls, server, line):
        server.parseCommand(line)
        server._state = _ServerErrorReadHeaderState

class _ServerErrorReadHeaderState:
    """Intercept headers from client to server"""
    @classmethod
    def lineReceived(cls, server, line):
        if not line or line == '':
            server.endOfHeaders()
            server.respondWithServerError()
        else:
            server.parseHeader(line)
