import hashlib
import struct

class Constants:
    # Handshake message types
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

    # Record content types
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

class TLSException(Exception):
    """Exception parsing TLS message"""
    pass


class Record:
    """Wrapper around a buffer representing a TLS/SSL record.

    Meant for parsing records not creatig them. Does not modify buffer."""

    HEADER_LENGTH = 5  # Type, 2 bytes of version and 2 bytes of length

    def __init__(self, buffer):
        """Create a Record object around given buffer."""
        if len(buffer) < self.HEADER_LENGTH:
            raise TLSException("Buffer too short ({} byes)".format(len(buffer)))
        self.view = memoryview(buffer)

    def content_type(self):
        """Return content type field of record"""
        return struct.unpack("!B", self.view[0])[0]

    def version(self):
        """Return tuple of major,minor version of protocol"""
        return struct.unpack("!BB", self.view[1:3].tobytes())

    def length(self):
        """Return protocol message length"""
        high_bits,low_bits = struct.unpack("!BB", self.view[3:5].tobytes())
        return (high_bits<<8) | low_bits

    def total_length(self):
        """Returns total length of record"""
        return self.length() + self.HEADER_LENGTH

    def handshake_messages(self):
        """Returns a generator of handshake messages in record.

        If not a handshake record, a TLSException is thrown."""
        type = self.content_type()
        if type != Constants.HANDSHAKE:
            raise TLSException("Record is not a Handshake record ({})".format(type))
        index = self.HEADER_LENGTH
        protocol_message_length = self.length()
        while index < self.HEADER_LENGTH + protocol_message_length:
            msg = HandshakeMessage(self.view[index:])
            yield msg
            index += msg.total_length()

    @classmethod
    def read_from_sock(cls, sock):
        """Read a record from the given socket."""
        header_buffer = bytearray(cls.HEADER_LENGTH)
        cls._read_bytes(sock,
                        cls.HEADER_LENGTH,
                        memoryview(header_buffer))
        header_record = cls(header_buffer)
        buffer = bytearray(header_record.total_length())
        buffer[0:cls.HEADER_LENGTH] = header_buffer
        view = memoryview(buffer)[cls.HEADER_LENGTH:]
        cls._read_bytes(sock, header_record.length(), view)
        return cls(buffer)

    @classmethod
    def _read_bytes(cls, sock, number_bytes, view):
        """Read number_bytes from socket into view"""
        bytes_read = 0
        while bytes_read < number_bytes:
            nbytes = sock.recv_into(view)
            bytes_read += nbytes
            view = view[nbytes:]
            
    def write_to_sock(self, sock):
        """Write the record to the given socket"""
        sock.send(self.view)

class HandshakeMessage:
    """Wrapper around a buffer representing a TLS/SSL Handshake message.

    Meant for parsing messages not creatig them. Does not modify buffer."""
    
    HEADER_LENGTH = 4  # Type plus 3 bytes of length

    def __init__(self, buffer):
        """Create a HandshakeMessage object around given buffer (or view).

        Buffer can be longer than handshake message (e.g., it can run to
        end of protocol message) and that will be handled."""
        # If buffer is a view, following is redundant, but doesn't seem
        # to cause harm.
        self.view = memoryview(buffer)
        # Trim view to actual length of message
        length = self.total_length()
        if length > len(self.view):
            raise TLSException("buffer ({}) shorter than handshake message ({})".format(len(buffer), length))
        self.view = self.view[:length]

    def type(self):
        """Return type field of message"""
        return struct.unpack("!B", self.view[0])[0]

    def total_length(self):
        """Return length of message including header"""
        return self.length() + self.HEADER_LENGTH

    def length(self):
        """Return length of message (excluding header)"""
        high_bits,mid_bits,low_bits = \
            struct.unpack("!BBB", self.view[1:4].tobytes())
        return (high_bits<<16) | (mid_bits<<8) | low_bits

    def certificates(self):
        """Returns a generator of certificates in handshake message.

        If not a Cerificate message, a TLSException is thrown."""
        # Skip over message header and three bytes providing length of all
        # certs
        view = self.view[self.HEADER_LENGTH+3:]
        while len(view) > 0:
            cert = Certificate(view)
            yield cert
            view = view[cert.total_length():]

class Certificate:
    """Wrapper around a buffer repsenting a certificate in a Certificate
    Handshake message.

    Meant for parsing certificates not creatig them. Does not modify buffer."""

    HEADER_LENGTH = 3  # 3 length bytes

    def __init__(self, buffer):
        """Create a Certificate object around given buffer (or view).

        Buffer can be longer than certificate message (e.g., it can run to
        end of protocol message) and that will be handled."""
        self.view = memoryview(buffer)
        # Trim view to actual length of message
        length = self.total_length()
        if length > len(self.view):
            raise TLSException("buffer ({}) shorter than certificate ({})".format(len(buffer), length))
        self.view = self.view[:length]

    def total_length(self):
        """Return length of message including header"""
        return self.length() + self.HEADER_LENGTH

    def length(self):
        """Return length of message (excluding header)"""
        high_bits,mid_bits,low_bits = \
            struct.unpack("!BBB", self.view[:3].tobytes())
        return (high_bits<<16) | (mid_bits<<8) | low_bits

    def md5_hash(self):
        """Return MD5 hash of certificate"""
        hash = hashlib.md5()
        hash.update(self.view[self.HEADER_LENGTH:])
        return hash.digest()
