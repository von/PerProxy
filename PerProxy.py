#!/usr/bin/env python

import binascii
import select
import socket
import thread

import PythonProxy
import TLS

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
                    for cert in cert_msg.certificates():
                        self._debug("Found certificate (len={})".format(len(cert)))
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

if __name__ == '__main__':
    start_server()
