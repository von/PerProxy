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

def decode_length(bytes):
    """Return length encoded in given bytes"""
    if isinstance(bytes, memoryview):
        bytes = bytes.tolist()
    length = 0
    for index in range(len(bytes)):
        length <<= 8
        length += bytes[index]
    return length
    
class Record:
    """Wrapper around a buffer representing a TLS/SSL record.

    Meant for parsing records not creatig them. Does not modify buffer."""

    HEADER_LENGTH = 5  # Type, 2 bytes of version and 2 bytes of length

    def __init__(self, buffer):
        """Create a Record object around given buffer."""
        if len(buffer) < self.HEADER_LENGTH:
            raise TLSException("Buffer too short ({} bytes)".format(len(buffer)))
        self.view = memoryview(buffer)

    def content_type(self):
        """Return content type field of record"""
        return struct.unpack("!B", self.view[0])[0]

    def version(self):
        """Return tuple of major,minor version of protocol"""
        return struct.unpack("!BB", self.view[1:3].tobytes())

    def length(self):
        """Return protocol message length"""
        return decode_length(self.view[3:5])

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
        view = self.view[index:index+protocol_message_length]
        while len(view) > 0:
            # Length is 2nd-4th bytes
            msg_len = decode_length(view[1:HandshakeMessage.HEADER_LENGTH])
            msg_start = 0
            msg_end = HandshakeMessage.HEADER_LENGTH + msg_len
            if len(view) < msg_end:
                raise RLSException("Buffer ({}) not long enough to hold handshake message ({})".format(len(view), msg_len))
            msg = HandshakeMessage(view[msg_start:msg_end])
            yield msg
            view = view[msg_end:]

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
    """A TLS/SSL Handshake message.

    Meant for parsing messages not creating them. Does not modify buffer."""
    
    HEADER_LENGTH = 4  # Type plus 3 bytes of length

    def __init__(self, data):
        """Create a HandshakeMessage object around given data"""
        if len(data) < self.HEADER_LENGTH:
            raise TLSException("Buffer too short ({} bytes)".format(len(data)))
        # If data is a view, following is redundant, but doesn't seem
        # to cause harm.
        self.data = memoryview(data)
        length = self.total_length()
        if len(data) < length:
            raise TLSException("Buffer too short ({}) to hold whole handshake message ({})".format(len(data), length))

    def type(self):
        """Return type field of message"""
        return struct.unpack("!B", self.data[0])[0]

    def total_length(self):
        """Return length of message including header"""
        return self.length() + self.HEADER_LENGTH

    def length(self):
        """Return length of message (excluding header)"""
        return decode_length(self.data[1:4])


class CertificateMessage(HandshakeMessage):

    CERTS_LENGTH_BYTES = 3  # 3 bytes of length of all certificates
    CERT_LENGTH_BYTES = 3  # 3 bytes at start of each certificate

    def __init__(self, data):
        HandshakeMessage.__init__(self, data)
        type = self.type()
        if type != Constants.CERTIFICATE:
            raise TLSException("Message is not a CERTIFICATE message ({})".format(type))
        length_of_certs = self.length_of_certs()
        if len(data) < length_of_certs:
            raise TLSException("Data ({}) is too short (<{}) to hold all certificates".format(len(data), length_of_certs))
        
    def length_of_certs(self):
        """Return length of all certificates"""
        # Bytes 5-7
        return decode_length(self.data[self.HEADER_LENGTH:self.HEADER_LENGTH+self.CERTS_LENGTH_BYTES])

    def certificates(self):
        """Returns a generator of certificates in message."""
        # Skip over header + length of all certificates bytes
        view = self.data[self.HEADER_LENGTH+self.CERTS_LENGTH_BYTES:]
        while len(view) > 0:
            cert_len = decode_length(view[:self.CERT_LENGTH_BYTES])
            # Skip over length bytes
            cert_start = self.CERT_LENGTH_BYTES
            cert_end = cert_start + cert_len
            if len(view) < cert_end:
                raise TLSException("data ({}) not long enough to hold certificate ({})".format(len(view), cert_len))
            cert = Certificate(view[cert_start:cert_end])
            yield cert
            view = view[cert_end:]

class Certificate:
    """TLS certificate"""

    def __init__(self, buffer):
        """Create a Certificate object around given buffer"""
        self.data = buffer

    def __len__(self):
        """Return length of certificate"""
        return len(self.data)

    def md5_hash(self):
        """Return MD5 hash of certificate"""
        hash = hashlib.md5()
        hash.update(self.data)
        return hash.digest()
