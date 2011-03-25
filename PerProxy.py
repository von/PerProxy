#!/usr/bin/env python

import binascii
import select
import socket

import PythonProxy
import TLS

from tlslite import constants
from tlslite import messages
from tlslite.utils import codec
from tlslite.utils import compat

SSL_RECORD_LENGTH = 5

class PerspectivesException(Exception):
    pass

class PerspectivesConnectionHandler(PythonProxy.ConnectionHandler):
    def method_CONNECT(self):
        self._connect_target(self.path)
        self.client.send(PythonProxy.HTTPVER+' 200 Connection established\n'+
                         'Proxy-agent: %s\n\n'%PythonProxy.VERSION)
        self.client_buffer = ''
        if self._is_https():
            try:
                self._perspectives_check_ssl_handshake()
            except PerspectivesException as e:
                # TODO: Handle this right. Send error back to client.
                self._debug("Perspectives error: {}".format(e))
                return
        self._read_write()  

    def _is_https(self):
        """Return True if this is a HTTPS connection"""
        # Following is assuming IPv4, should check with IPv6
        address, port = self.target.getpeername()
        return (port == 443)

    def _perspectives_check_ssl_handshake(self):
        """Passively parse the SSL handshake and check server cert with Perspectives"""
        self._debug("Parsing SSL Handshake")
        # Pass ClientHello through without parsing
        data = self.client.recv(PythonProxy.BUFLEN)
        self.target.send(data)
        # Read and parse server side of handshake
        server_done = False
        while not server_done:
            record = TLS.Record.read_from_sock(self.target)
            type = record.content_type()
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
                    for cert in msg.certificates():
                        self._debug("Found certificate (len={})".format(cert.length()))
                        digest = cert.md5_hash()
                        self._debug("Hash: {}".format(":".join([binascii.b2a_hex(b) for b in digest])))
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

    def _debug(self, msg):
        print msg

if __name__ == '__main__':
    PythonProxy.start_server(handler=PerspectivesConnectionHandler)
