#!/usr/bin/env python

import M2Crypto

import argparse
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

from Perspectives import Checker
from Perspectives import PerspectivesException
from Perspectives import Service, ServiceType

from TLS import Fingerprint

def recvall(s, buflen=8192):
    """Given a non-blocking ssl.SSLSocket or M2Crypto.SSL.Connection read all pending data."""
    chunks = []
    while True:
        try:
            # SSLSocket will raise ssl.SSLError if no data pending
            #           or return 0 bytes on EOF
            # Connection will return None
            data = s.recv(buflen)
        except ssl.SSLError:
            data = None
        if data is None or len(data) == 0:
            break
        chunks.append(data)
    return "".join(chunks)


# Not order of inherited classes here is important
class ProxyServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class Handler(SocketServer.BaseRequestHandler):

    ca = None
    checker = None

    def setup(self):
        self.logger = logging.getLogger("Handler")

    def handle(self):
        self.logger.info("Connection received.")
        header = self.read_header()
        (method, path, protocol) = header[0].strip().split()
        hostname, port_str = path.split(":")
        port = int(port_str)

        self.logger.info("Connecting to {}:{}".format(hostname, port))
        server_sock = self.connect_to_server(hostname, port)
        server_cert = server_sock.get_peer_cert()
        server_name = server_cert.get_subject()
        self.logger.debug("Server subject is {}".format(server_name.as_text()))

        self.logger.info("Checking certificate with Perspectives")
        fingerprint = Fingerprint.from_M2Crypto_X509(server_cert)
        service = Service(hostname, port)
        try:
            self.checker.check_seen_fingerprint(service, fingerprint)
        except PerspectivesException as e:
            self.logger.error("Perspectives check failed: {}".format(str(e)))
            return
        self.logger.debug("Connection to server established")

        cert_file, key_file = self.get_server_creds(hostname)
        self.logger.debug("Responding to client.")
        try:
            self.request.send("{} {} {}\n".format("HTTP/1.1",
                                                  "200",
                                                  "Connection established"))
            self.request.send("Proxy-agent: SSL-MITM-1.0\n")
            self.request.send("\n")
        except Exception as e:
            self.logger.error("Error responding to client: {}".format(str(e)))
            return
        self.logger.debug("Starting SSL with client...")
        try:
            ssl_sock = ssl.wrap_socket(self.request,
                                       keyfile = key_file,
                                       certfile = cert_file,
                                       server_side = True)
        except ssl.SSLError as e:
            self.logger.error("Error starting SSL with client: {}".format(str(e)))
            return
        self.logger.debug("SSL with client successful")
        self.pass_through(ssl_sock, server_sock)
        self.request.close()
        server_sock.close()
        self.logger.info("Done.")

    def pass_through(self, client, server):
        """Pass data back and forth between client and server"""
        self.logger.info("Entering pass_through mode")
        def name(s):
            if s == client:
                return "client"
            elif s == server:
                return "server"
            else:
                raise Exception("Unknown socket {}".format(s.fileno()))
        def out_sock(s):
            if s == client:
                return server
            elif s == server:
                return client
            else:
                raise Exception("Unknown socket {}".format(s.fileno()))
        client.setblocking(False)
        server.setblocking(False)
        socks = [client, server]
        done = False
        while not done:
            (read_ready, write_ready, error) = select.select(socks, [], socks)
            if len(error) != 0:
                self.logger.info("Got exception from {}".format(name(error[0])))
                break
            for s in read_ready:
                self.logger.debug("Reading from {}".format(name(s)))
                try:
                    data = recvall(s)
                except IOError as e:
                    self.logger.error("Error reading from {}: {}".format(name(s),
                                                                    str(e)))
                    done = True
                    break
                out = out_sock(s)
                if len(data) == 0:
                    # HACK: M2Crypto.SSL.Connection seems to randomly
                    # return 0 bytes even though select says it is
                    # read ready. So ignore 0 bytes read from server
                    if s == server:
                        pass
                    else:
                        self.logger.info("Got EOF from {}".format(name(s)))
                        done = True
                        break
                else:
                    self.logger.debug("Writing {} bytes to {}".format(len(data),
                                                                 name(out)))
                    out.sendall(data)
        self.logger.info("Pass through done.")

    def connect_to_server(self, hostname, port):
        """Connect to given hostname and port and return SSL.Connection

        We use M2Crypto.SSL.Connection here because it allows us to get
        the server certificate without validating it (with the python
        ssl module does not allow."""
        context = M2Crypto.SSL.Context("sslv3")
        s = M2Crypto.SSL.Connection(context)
        s.connect((hostname, port))
        return s

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

    def read_header(self):
        """Read and return header as a list of strings"""
        header = []
        while True:
            line = self.readline()
            header.append(line)
            if line.strip() == "":
                break
        return header

    def readline(self):
        line = ""
        while line.find("\n") == -1:
            line += self.request.recv(1)
        return line

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
