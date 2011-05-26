"""HTTP query client based on asyncore

Adapted from:

http://blog.doughellmann.com/2009/03/pymotw-asyncore.html

and

http://pythonwise.blogspot.com/2010/02/parse-http-response.html
"""

import asyncore
from httplib import HTTPResponse
import logging
import socket
from StringIO import StringIO
import urlparse

class ResponseBuffer(StringIO):
    def makefile(self, *args, **kw):
        return self

class HTTP_dispatcher(asyncore.dispatcher):

    def __init__(self, url, map=None):
        self.url = url
        self.logger = logging.getLogger("HTTP_dispatcher")
        self.parsed_url = urlparse.urlparse(url)
        if self.parsed_url.netloc.find(":") == -1:
            hostname = self.parsed_url.netloc
            port = 80
        else:
            hostname, port_str = self.parsed_url.netloc.split(":")
            port = int(port_str)
        asyncore.dispatcher.__init__(self, map=map)
        self.write_buffer = 'GET %s HTTP/1.0\r\n\r\n' % self.url
        self.read_buffer = ResponseBuffer()
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (hostname, port)
        self.logger.debug('connecting to %s', address)
        self.connect(address)

    def handle_connect(self):
        self.logger.debug('handle_connect()')

    def handle_close(self):
        self.logger.debug('handle_close()')
        self.close()

    def writable(self):
        is_writable = (len(self.write_buffer) > 0)
        if is_writable:
            self.logger.debug('writable() -> %s', is_writable)
        return is_writable
    
    def readable(self):
        self.logger.debug('readable() -> True')
        return True

    def handle_write(self):
        sent = self.send(self.write_buffer)
        self.logger.debug('handle_write() -> "%s"', self.write_buffer[:sent])
        self.write_buffer = self.write_buffer[sent:]

    def handle_read(self):
        data = self.recv(8192)
        self.logger.debug('handle_read() -> %d bytes', len(data))
        self.read_buffer.write(data)

    def get_response(self):
        self.read_buffer.seek(0)
        response = HTTPResponse(self.read_buffer)
        response.begin()  # Process the response
        return response
