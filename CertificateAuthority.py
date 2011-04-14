"""Certificate Authority"""

from M2Crypto import EVP, X509

class CertificateAuthority:
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    @classmethod
    def from_file(cls, cert_file, key_file):
        cert = X509.load_cert(cert_file)
        key = EVP.load_key(key_file)
        return cls(cert, key)

