#!/usr/bin/env python

import argparse
import logging
import select
import socket
import sys
import thread

from Perspectives import Checker
from Perspectives import PerspectivesException
from Perspectives import Service, ServiceType
import PythonProxy
import TLS

class PerspectivesConnectionHandler(PythonProxy.ConnectionHandler):
    def method_CONNECT(self):
        hostname, port = self._parse_address(self.path)
        if port == 443:
            self._debug("Doing perspectives checking on HTTPS connection to {}".format(hostname))
            try:
                self.perspectives_checker = Checker(Service(hostname,
                                                            port,
                                                            ServiceType.SSL))
            except PerspectivesException as e:
                self._debug("Perspectives check failed: {}".format(e))
                err_str = PythonProxy.HTTPVER + " " + \
                    "502 Perspectives error: " + str(e) + "\n" + \
                    'Proxy-agent: {}\n\n'.format(PythonProxy.VERSION)
                self.client.send(err_str)
                self.client.close()
                return 
        self._connect_target(self.path)
        self.client.send(PythonProxy.HTTPVER+' 200 Connection established\n'+
                         'Proxy-agent: %s\n\n'%PythonProxy.VERSION)
        self.client_buffer = ''
        if port == 443:
            self._check_ssl_handshake()
            # Will not return on error
        self._read_write()  

    def _check_ssl_handshake(self):
        """Monitor SSL handshake and make sure service certificate matches expected

        Expected is in self.expected_cert_pem"""
        self._debug("Parsing SSL Handshake")
        # Pass ClientHello through without parsing
        data = self.client.recv(PythonProxy.BUFLEN)
        self.target.send(data)
        # Read and parse server side of handshake
        server_done = False
        while not server_done:
            record = TLS.Record.read_from_sock(self.target)
            type = record.content_type()
            self._debug("Read record of type {}".format(type))
            if type != TLS.Constants.HANDSHAKE:
                self._debug("Found non-Handshake message ({})".format(type))
                record.write_to_sock(self.client)
                break
            version_major,version_minor = record.version()
            self._debug(
                "Record version: {}.{} length: {}".format(
                    version_major, version_minor, record.length()))
            # Parse all handshake messages looking for a Certificate message
            for msg in record.handshake_messages():
                type = msg.type()
                length = msg.length()
                self._debug("Handshake message: type = {} length = {}".format(type, length))
                if type == TLS.Constants.CERTIFICATE:
                    self._debug("Found Certificate message")
                    cert_msg = TLS.CertificateMessage(msg.data)
                    server_cert = cert_msg.get_server_certificate()
                    try:
                        self.perspectives_checker.check_seen_fingerprint(server_cert.fingerprint())
                    except PerspectivesException as e:
                        self._debug(e)
                        # XXX Punting. Is there a graceful way to shut
                        # down the connection at this point?
                        return
                    break
                elif type == TLS.Constants.SERVER_HELLO_DONE:
                    server_done = True
                    self._debug("Server done.")
                    break
                else:
                    self._debug("Skipping handshake message (type = {})".format(type))
            self._debug("Done processing record")
            record.write_to_sock(self.client)
        self._debug("Perspectives handshake check done")

    @classmethod
    def _parse_address(cls, target):
        """Given a target of the form hostname[:port] return hostname and port"""
        components = target.split(":")
        hostname = components[0]
        port = int(components[1]) if len(components) > 1 else 80
        return (hostname, port)

    def _debug(self, msg):
        print msg


def start_server(host='localhost', port=8080, IPv6=False, timeout=60,
                  handler=PerspectivesConnectionHandler):
    if IPv6==True:
        soc_type=socket.AF_INET6
    else:
        soc_type=socket.AF_INET
    soc = socket.socket(soc_type)
    # Allow for quick reuse of port
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind((host, port))
    print "Serving on %s:%d."%(host, port)#debug
    soc.listen(0)
    while 1:
        thread.start_new_thread(handler, soc.accept()+(timeout,))


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
    parser.add_argument("-N", "--notaries-file",
                        type=str, default="./http_notary_list.txt",
                        help="specify notaries file", metavar="filename")
    parser.add_argument("-p", "--port", dest="proxy_port",
                        type=int, default=8080,
                        help="specify service port", metavar="port")
    args = parser.parse_args()

    output_handler.setLevel(args.output_level)

    Checker.init_class(notaries_file = args.notaries_file)
    output.debug("Read configuration for {} notaries from configuration {}".format(len(Checker.notaries), args.notaries_file))
    Checker.init_class()
    start_server(port=args.proxy_port)  # Does not return

if __name__ == '__main__':
    sys.exit(main())
