#!/usr/bin/env python

import M2Crypto

import argparse
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

# Not order of inherited classes here is important
class ProxyServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class Handler(SocketServer.BaseRequestHandler):

    ca = None

    def handle(self):
        output = logging.getLogger()
        output.info("Connection received.")
        header = self.read_header()
        (method, path, protocol) = header[0].strip().split()
        hostname, port_str = path.split(":")
        port = int(port_str)

        output.info("Connecting to {}:{}".format(hostname, port))
        server_sock = self.connect_to_server(hostname, port)
        server_cert = server_sock.get_peer_cert()
        server_name = server_cert.get_subject()
        output.debug("Server subject is {}".format(server_name.as_text()))

        output.debug("Connection to server established")
        output.debug("Responding to client.")
        cert_file, key_file = self.get_server_creds(hostname)
        self.request.send("{} {} {}\n".format("HTTP/1.1",
                                              "200",
                                              "Connection established"))
        self.request.send("Proxy-agent: SSL-MITM-1.0\n")
        self.request.send("\n")
        output.debug("Starting SSL with client...")
        ssl_sock = ssl.wrap_socket(self.request,
                                   keyfile = key_file,
                                   certfile = cert_file,
                                   server_side = True)
        output.debug("SSL with client successful")
        self.pass_through(ssl_sock, server_sock)
        self.request.close()
        server_sock.close()

    def pass_through(self, client, server, buflen=8192):
        """Pass data back and forth between client and server"""
        output = logging.getLogger()
        output.info("Entering pass_through mode")
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
        socks = [client, server]
        while True:
            (read_ready, write_ready, error) = select.select(socks, [], socks)
            if len(error) != 0:
                output.info("Got exception from {}".format(name(error[0])))
                break
            for s in read_ready:
                output.debug("Reading from {}".format(name(s)))
                try:
                    data = s.recv(buflen)
                except Exception as e:
                    output.error("Error reading from {}: {}".format(name(s),
                                                                    str(e)))
                    return  # XXX Cleaner way to handle this?
                if len(data) > 0:
                    out = out_sock(s)
                    output.debug("Writing {} bytes to {}".format(len(data),
                                                                 name(out)))
                    out.sendall(data)

    def connect_to_server(self, hostname, port):
        """Connect to given hostname and port and return SSL.Connection"""
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

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger()
    output.setLevel(logging.DEBUG)
    output_handler = logging.StreamHandler(sys.stdout)  # Default is sys.stderr
    # Set up formatter to just print message without preamble
    output_handler.setFormatter(logging.Formatter("%(message)s"))
    output.addHandler(output_handler)

    # Argument parsing
    parser = argparse.ArgumentParser(
        description=__doc__, # printed with -h/--help
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
    # Only allow one of debug/quiet mode
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-d", "--debug",
                                 action='store_const', const=logging.DEBUG,
                                 dest="output_level", default=logging.INFO,
                                 help="print debugging")
    verbosity_group.add_argument("-q", "--quiet",
                                 action="store_const", const=logging.WARNING,
                                 dest="output_level",
                                 help="run quietly")
    parser.add_argument("-C", "--ca-cert-file",
                        type=str, default="./ca-cert.pem",
                        help="specify CA cert file", metavar="filename")
    parser.add_argument("-K", "--ca-key-file",
                        type=str, default="./ca-key.pem",
                        help="specify CA key file", metavar="filename")
    parser.add_argument("-p", "--port", dest="proxy_port",
                        type=int, default=8080,
                        help="specify service port", metavar="port")
    args = parser.parse_args()

    output_handler.setLevel(args.output_level)

    output.debug("Loading CA from {} and {}".format(args.ca_cert_file,
                                                    args.ca_key_file))
    Handler.ca = CertificateAuthority.from_file(args.ca_cert_file,
                                                args.ca_key_file)

    output.info("Starting SSL MITM proxy on {} port {}".format("localhost",
                                                               args.proxy_port))
    server = ProxyServer(("localhost", args.proxy_port), Handler)
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
