"""Class for representing a certificate fingerprint"""

import binascii

from Exceptions import FingerprintException

class Fingerprint:
    """Fingerprint from certificate"""
    
    def __init__(self, data):
        """Create a Fingerprint instance with given binary data"""
        self.data = bytes(data)

    @classmethod
    def from_string(cls, str):
        """Create Fingerprint from hex colon-separated word format"""
        data = bytearray([int(n,16) for n in str.split(":")])
        return cls(data)

    @classmethod
    def from_M2Crypto_X509(cls, cert):
        """Create Fingerprint from M2Crypto.X509.X509 instance."""
        # Data will be hex string without colons
        fingerprint = cert.get_fingerprint()
        try:
            data = binascii.a2b_hex(fingerprint)
        except Exception as e:
            raise FingerprintException("Error parsing fingerprint \"%s\": %s" % (fingerprint, str(e)))
        return cls(data)

    def __str__(self, sep=":"):
        return sep.join([binascii.b2a_hex(b) for b in self.data])

    def __eq__(self, other):
        return self.data == other.data

    def __ne__(self, other):
        return self.data != other.data
