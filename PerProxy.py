#!/usr/bin/env python

import M2Crypto

import argparse
import BaseHTTPServer
import ConfigParser
import logging
import os
import select
import socket
import SocketServer
import ssl
import sys
import tempfile
import threading
import time

from CertificateAuthority import CertificateAuthority
from Server import Server

from Perspectives import Checker
from Perspectives import PerspectivesException
from Perspectives import Service, ServiceType

from TLS import Fingerprint


# Not order of inherited classes here is important
class ProxyServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class Handler(SocketServer.BaseRequestHandler):

    ca = None
    checker = None

    PROTOCOL_VERSION = "HTTP/1.1"

    AGENT_STRING = "SSL-MITM-1.0"

    HTML_ERROR_TEMPLATE = "\n".join([
            "<html>",
            "<title>PerProxy Server Error: {title}</title>",
            "<body>",
            "<h1>PerProxy Server Error</h1>",
            "<p>The PerProxy server encountered an error with the server:</p>",
            "<p>{error}</p>",
            "</body>",
            "</html>"
            ])

    def setup(self):
        self.logger = logging.getLogger("Handler")

    def handle(self):
        self.logger.info("Connection received.")
        hostname, port = self.parse_connect_command()

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
        except Exception as e:
            self.logger.error("Deferring handling error connecting to server: {}".format(e))
            server_error = e

        try:
            cert_file, key_file = self.get_server_creds(hostname)
            self.logger.debug("Responding to client.")
            self.respond(200)
            self.logger.debug("Starting SSL with client...")
            self.start_ssl(key_file, cert_file)
            self.logger.debug("SSL with client successful")
        except IOError as e:
            self.logger.error("Error responding to client: {}".format(str(e)))
            return
        except ssl.SSLError as e:
            self.logger.error("Error starting SSL with client: {}".format(str(e)))
            return

        if server_error:
            # We got an error of some sort during setup with server.
            # Instead of connecting client to server, we're going to
            # sent the client a hunk of html describing the error.
            self.logger.info("Handling deferred server error: {}".format(server_error))
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
        
        self.logger.info("Connecting to {}:{}".format(hostname, port))
        try:
            server = Server(hostname, port)
        except Exception as e:
            self.logger.error("Error connecting to {}:{}: {}".format(hostname,
                                                                     port,
                                                                     e))
            raise
        self.logger.debug("Server subject is {}".format(server.subject().as_text()))                             

        self.logger.info("Checking certificate with Perspectives")
        try:
            fingerprint = server.get_fingerprint()
            service = Service(hostname, port)
            self.checker.check_seen_fingerprint(service, fingerprint)
        except PerspectivesException as e:
            self.logger.error("Perspectives check failed: {}".format(str(e)))
            raise

        self.logger.debug("Connection to server established")
        return server

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
        self.send("{} {} {}\n".format(self.PROTOCOL_VERSION,
                                      code,
                                      msg))
        self.send("Proxy-agent: {}\n".format(self.AGENT_STRING))
        self.send("\n")

    def start_ssl(self, key_file, cert_file):
        """Start SSL with client."""
        ssl_sock = ssl.wrap_socket(self.request,
                                   keyfile = key_file,
                                   certfile = cert_file,
                                   server_side = True)
        self.orig_request = self.request
        self.request = ssl_sock

    def pass_through(self, server):
        """Pass data back and forth between client and server"""
        self.logger.info("Entering pass_through mode")
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
        while not done:
            (read_ready, write_ready, error) = select.select(socks,[], socks)
            if len(error) != 0:
                instance = instances[error[0]]
                self.logger.info("Got exception from {}".format(instance))
                break
            for s in read_ready:
                instance = instances[s]
                self.logger.debug("Reading from {}".format(instance))
                try:
                    data = instance.recvall()
                except IOError as e:
                    self.logger.error("Error reading from {}: {}".format(instance,
                                                                         str(e)))
                    done = True
                    break
                out = peer[instance]
                if len(data) == 0:
                    # HACK: M2Crypto.SSL.Connection seems to randomly
                    # return 0 bytes even though select says it is
                    # read ready. So ignore 0 bytes read from server
                    if instance == server:
                        pass
                    else:
                        self.logger.info("Got EOF from {}".format(s))
                        done = True
                        break
                else:
                    self.logger.debug("Writing {} bytes to {}".format(len(data),
                                                                      out))
                    out.sendall(data)
        self.logger.info("Pass through done.")

    def handle_server_error(self, server_error):
        """Handle a error connecting to the server.

        In stead of passing data back and forth, we mimic the server and
        send back a web page describing the error."""
        # First we read request and headers client meant to send to server
        method, path, protocol, headers = self.read_header()
        self.logger.debug("Client request was: {} {} {}".format(method,
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
        self.send(self.HTML_ERROR_TEMPLATE.format(**values))
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
            raise IOError("Client sent unexpected command \"{}\"".format(method))
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
                data = self.request.recv(buflen)
            except ssl.SSLError:
                data = None
            if data is None or len(data) == 0:
                break
            chunks.append(data)
        return "".join(chunks)

    def __str__(self):
        return "client at {}:{}".format(self.client_address[0],
                                        self.client_address[1])

    def get_server_creds(self, hostname):
        """Return credentials for the given host"""
        cert, key = self.ca.generate_ssl_credential(hostname)
        fd, cert_file = tempfile.mkstemp()
        os.close(fd)
        cert.save_pem(cert_file)
        fd, key_file = tempfile.mkstemp()
        os.close(fd)
        key.save_key(key_file, cipher=None)  # cipher=None -> save in the clear
        return cert_file, key_file

def parse_args(argv):
    """Parse our command line arguments"""
    # Parse any conf_file specification
    # We make this parser with add_help=False so that
    # it doesn't parse -h and print help.
    conf_parser = argparse.ArgumentParser(
        # Turn off help, so we print all options in response to -h
        add_help=False
        )
    conf_parser.add_argument("-c", "--conf_file",
                        help="Specify config file", metavar="FILE")
    args, remaining_argv = conf_parser.parse_known_args(argv[1:])
    defaults = {
        "output_level" : logging.INFO,
        "ca_cert_file" : "./ca-cert.crt",
        "ca_key_file" : "./ca-key.pem",
        "notaries_file" : "./http_notary_list.txt",
        "proxy_hostname" : "localhost",
        "proxy_port" : 8080,
        }
    if args.conf_file:
        # Mappings from configuraition file to options
        conf_mappings = [
            # ((section, option), option)
            (("CA", "CertFile"), "ca_cert_file"),
            (("CA", "KeyFile"), "ca_key_file"),
            (("Perspectives", "NotaryFile"), "notaries_file"),
            (("Proxy", "Hostname"), "proxy_hostname"),
            (("Proxy", "Port"), "proxy_port")
            ]
        config = ConfigParser.SafeConfigParser()
        config.read([args.conf_file])
        for sec_opt, option in conf_mappings:
            if config.has_option(*sec_opt):
                value = config.get(*sec_opt)
                defaults[option] = value

    # Parse rest of arguments
    # Don't surpress add_help here so it will handle -h
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        parents=[conf_parser],
        # print script description with -h/--help
        description=__doc__,
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.set_defaults(**defaults)
    # Only allow one of debug/quiet mode
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-d", "--debug",
                                 action='store_const', const=logging.DEBUG,
                                 dest="output_level", 
                                 help="print debugging")
    verbosity_group.add_argument("-q", "--quiet",
                                 action="store_const", const=logging.WARNING,
                                 dest="output_level",
                                 help="run quietly")
    parser.add_argument("-C", "--ca-cert-file",
                        type=str, default="./ca-cert.crt",
                        help="specify CA cert file", metavar="filename")
    parser.add_argument("-K", "--ca-key-file",
                        type=str, default="./ca-key.pem",
                        help="specify CA key file", metavar="filename")
    parser.add_argument("-N", "--notaries-file",
                        type=str, default="./http_notary_list.txt",
                        help="specify notaries file", metavar="filename")
    parser.add_argument("-p", "--port", dest="proxy_port",
                        type=int, default=8080,
                        help="specify service port", metavar="port")
    args = parser.parse_args(remaining_argv)
    return args

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger()
    output.setLevel(logging.DEBUG)
    output_handler = logging.StreamHandler(sys.stdout)  # Default is sys.stderr
    output_handler.setFormatter(logging.Formatter("%(threadName)s:%(name)s: %(message)s"))
    output.addHandler(output_handler)

    args = parse_args(argv)

    output_handler.setLevel(args.output_level)

    output.debug("Initializing Perspectives checker with notaries from {}".format(args.notaries_file))

    output.debug("Loading CA from {} and {}".format(args.ca_cert_file,
                                                    args.ca_key_file))
    Handler.ca = CertificateAuthority.from_file(args.ca_cert_file,
                                                args.ca_key_file)
    Handler.checker = Checker(notaries_file = args.notaries_file)

    output.info("Starting SSL MITM proxy on {} port {}".format("localhost",
                                                               args.proxy_port))
    server = ProxyServer((args.proxy_hostname, args.proxy_port), Handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.setDaemon(True)
    server_thread.start()
    output.info("Server thread started")

    while True:
        try:
            time.sleep(100)
        except KeyboardInterrupt as e:
            return(0)

if __name__ == '__main__':
    sys.exit(main())
