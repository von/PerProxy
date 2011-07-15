"""ProxyServer and Handler class"""

import BaseHTTPServer
import errno
import logging
import select
import ssl
import socket
import SocketServer
import string

import M2Crypto

from Perspectives import PerspectivesException
from Perspectives import Service

from Server import Server

# Not order of inherited classes here is important
class ProxyServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Handle an uncaught exception in handle()"""
        logger = logging.getLogger(self.__class__.__name__)
        logger.exception("Uncaught exception responding to %s" % client_address[0])

class Handler(SocketServer.BaseRequestHandler):

    ca = None
    checker = None
    whitelist = None

    PROTOCOL_VERSION = "HTTP/1.1"

    AGENT_STRING = "SSL-MITM-1.0"

    HTML_ERROR_TEMPLATE = None

    def handle(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("Connection received.")
        
        hostname, port = self.parse_connect_command()
        self.logger.info("Target is %s:%s" % (hostname, port))
        self.logger = logging.LoggerAdapter(self.logger,
                                            { "target" : hostname })

        # Sending errors back in response to the CONNECT command
        # doesn't work as browsers seem to ignore response code and
        # accompanying text.
        # 
        # Instead we defer reporting the error to the client until
        # after we establish an SSL connection with the client, and
        # then we respond to the command from the client within the
        # proxied connection.
        server_error = None
        try:
            server = self.connect_to_server(hostname, port)
        except PerspectivesException as e:
            self.logger.error("Deferring handling error connecting to server: %s" % e)
            server_error = e
        except socket.gaierror as e:
            server_error = "Unknown host \"%s\"" % hostname
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                server_error = "Connection to \"%s\" refused." % hostname
            else:
                server_error = e
        except Exception as e: 
            self.logger.exception(e)
            self.logger.error("Deferring handling error connecting to server: %s" % e)
            server_error = e

        try:
            cert_file, key_file = self.ca.get_ssl_credentials(hostname)
            self.logger.debug("Responding to client.")
            self.logger.debug("Cert = %s" % cert_file)
            self.logger.debug("Key = %s" % key_file)
            self.respond(200)
            self.logger.debug("Starting SSL with client...")
            self.start_ssl(key_file, cert_file)
            self.logger.debug("SSL with client successful")
        except IOError as e:
            self.logger.error("Error responding to client: %s" % str(e))
            return
        except ssl.SSLError as e:
            self.logger.error("Error starting SSL with client: %s" % str(e))
            return

        if server_error:
            # We got an error of some sort during setup with server.
            # Instead of connecting client to server, we're going to
            # sent the client a hunk of html describing the error.
            self.logger.info("Handling deferred server error: %s" % server_error)
            self.handle_server_error(server_error)
        else:
            # Good connections with client and server, just start
            # passing through traffic.
            self.pass_through(server)
            server.close()
        self.request.close()
        self.logger.info("Done.")

    def connect_to_server(self, hostname, port):
        """Handle connection to desired server

        Handles checking of certificate.

        Return Server instance."""
        
        self.logger.info("Connecting to %s:%s" % (hostname, port))
        try:
            server = Server(hostname, port)
        except Exception as e:
            self.logger.error("Error connecting to %s:%s: %s" % (hostname,
                                                                     port,
                                                                     e))
            raise

        self.logger.debug("Server subject is %s" % (server.subject().as_text()))                             
        self.check_server(server)
        
        self.logger.debug("Connection to server established")
        return server

    def check_server(self, server):
        """Do checks on server."""
        if self.whitelist:
            self.logger.debug("Checking whitelist for %s" % (server.hostname))
            if self.whitelist.contains(server.hostname):
                self.logger.info("Server %s is on whitelist." % (server.hostname))
                return

        self.logger.info("Checking certificate with Perspectives")
        try:
            fingerprint = server.get_fingerprint()
            service = Service(server.hostname, server.port)
            self.checker.check_seen_fingerprint(service, fingerprint)
        except PerspectivesException as e:
            self.logger.error("Perspectives check failed: %s" % str(e))
            raise

    def send(self, msg):
        self.request.send(msg)

    def sendall(self, msg):
        self.request.sendall(msg)

    def make_nonblocking(self):
        self.request.setblocking(False)

    def respond(self, code, msg=None):
        """Respond to client with given code.

        If msg is not provided, uses default for code."""
        msg = msg if msg is not None else \
            BaseHTTPServer.BaseHTTPRequestHandler.responses[code]
        self.send("%s %s %s\n" % (self.PROTOCOL_VERSION,
                                      code,
                                      msg))
        self.send("Proxy-agent: %s\n" % self.AGENT_STRING)
        self.send("\n")

    def start_ssl(self, key_file, cert_file):
        """Start SSL with client."""
        self.ssl_context = M2Crypto.SSL.Context("sslv3")
        self.ssl_context.load_cert(certfile = cert_file,
                                   keyfile = key_file)
        ssl_sock = M2Crypto.SSL.Connection(self.ssl_context, self.request)
        # Experimentally, these seem to be the right calls to have M2Crypto
        # accept an SSL HandShake as a server on an existing socket.
        ssl_sock.setup_ssl()
        ssl_sock.accept_ssl()
        self.orig_request = self.request
        self.request = ssl_sock

    def pass_through(self, server):
        """Pass data back and forth between client and server"""
        self.logger.info("Entering pass_through mode")
        none_read_threshold = 5
        self.make_nonblocking()
        server.make_nonblocking()
        # Mapping from sockets to instances
        instances = {
            self.request : self,
            server.sock : server
            }
        socks = instances.keys()
        # Mapping from instances to peers
        peer = {
            self : server,
            server : self
            }
        done = False
        none_read_count = 0
        while not done:
            (read_ready, write_ready, error) = select.select(socks,[], socks)
            if len(error) != 0:
                instance = instances[error[0]]
                self.logger.info("Got exception from %s" % instance)
                break
            for s in read_ready:
                instance = instances[s]
                self.logger.debug("Reading from %s" % instance)
                try:
                    data = instance.recvall()
                except IOError as e:
                    self.logger.error("Error reading from %s: %s" % (instance,
                                                                         str(e)))
                    done = True
                    break
                if data is None:
                    # M2Crypto.SSL.Connection returns None sometimes.
                    # This does not indicate an EOF.  Be done if we
                    # see a lot of None reads in a row, might be causing
                    # high CPU consumption problems.
                    none_read_count += 1
                    if none_read_count < none_read_count_threshold:
                        self.logger.debug("Ignoring read of None from %s" % instance)
                        continue
                    else:
                        self.logger.info("Reach threshold (%d) for None reads" % none_read_count_threshold)
                        done = True
                        break
                none_read_count = 0
                if len(data) == 0:
                    self.logger.info("Got EOF from %s" % instance)
                    done = True
                    break
                out = peer[instance]
                self.logger.debug("Writing %s bytes to %s" % (len(data),
                                                                  out))
                out.sendall(data)
            else:
                self.logger.debug("select() returned without anything for us to do")
        self.logger.info("Pass through done.")

    def handle_server_error(self, server_error):
        """Handle a error connecting to the server.
        
        server_error can be an Exception or a string.

        In stead of passing data back and forth, we mimic the server and
        send back a web page describing the error."""
        # First we read request and headers client meant to send to server
        method, path, protocol, headers = self.read_header()
        self.logger.debug("Client request was: %s %s %s" % (method,
                                                                path,
                                                                protocol))
        # TODO: We may want to respond differently depending on information
        #       in the headers. E.g., if the client isn't expecting HTML
        #       then we don't send HTML (not sure what we should do).
        self.respond(502, str(server_error))
        values = {
            "title" : str(server_error),
            "error" : str(server_error),
            }
        template = string.Template(self.HTML_ERROR_TEMPLATE)
        html = template.substitute(values)
        self.send(html)
        self.logger.debug("Error response sent.")
        
    def read_header(self):
        """Read and return header

        Return is (method, path, protocol, header_lines as a list of strings)"""
        # First line is request: GET /foo HTTP/1.0
        request = self.readline()
        (method, path, protocol) = request.strip().split()
        
        # Followed by N header lines until a blank line
        header_lines = []
        while True:
            line = self.readline()
            if line.strip() == "":
                break
            header_lines.append(line)
        return (method, path, protocol, header_lines)

    def parse_connect_command(self):
        """Parse a header which is expected to be a CONNECT command

        Returns target_hostname and target_port."""
        (method, path, protocol, header_lines) = self.read_header()
        if method != "CONNECT":
            raise IOError("Client sent unexpected command \"%s\"" % method)
        hostname, port_str = path.split(":")
        port = int(port_str)
        return hostname, port

    def readline(self):
        line = ""
        while line.find("\n") == -1:
            line += self.request.recv(1)
        return line

    def recvall(self, buflen=8192):
        """Given a non-blocking socket, read all panding data.

        Socket can be ssl.SSLSocket or M2Crypto.SSL.Connection."""
        chunks = []
        while True:
            try:
                # SSLSocket will raise ssl.SSLError if no data pending
                #           or return 0 bytes on EOF
                self.logger.debug("recv()...")
                data = self.request.recv(buflen)
                if data is None:
                    self.logger.debug("...returned None")
                else:
                    self.logger.debug("...returned %d bytes" % len(data))
            except ssl.SSLError:
                data = None
            if data is None or len(data) == 0:
                break
            chunks.append(data)
        return "".join(chunks)

    def __str__(self):
        return "client at %s:%s" % (self.client_address[0],
                                        self.client_address[1])
