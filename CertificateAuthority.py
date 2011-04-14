"""Certificate Authority"""

from M2Crypto import EVP, m2, RSA, X509

class CertificateAuthority:
    def __init__(self, cert, key, serial_number = None):
        self.cert = cert
        self.key = key
        self.serial_number = serial_number \
            if serial_number is not None else cert.get_serial_number() + 1

    @classmethod
    def from_file(cls, cert_file, key_file):
        cert = X509.load_cert(cert_file)
        key = EVP.load_key(key_file)
        return cls(cert, key)

    def generate_ssl_credential(self,
                                hostname,
                                key_length=2048,
                                lifetime=24*60*60,
                                sign_hash="sha1"):
        """Generate credentials for a given target.

        Returns a tuple of X509 certificate and EVP key."""
        rsa_key = RSA.gen_key(key_length, m2.RSA_F4)
        key = EVP.PKey()
        key.assign_rsa(rsa_key)
        cert = X509.X509()
        cert.set_serial_number(self.serial_number)
        self.serial_number += 1
        cert.set_version(2)
        name = self.get_relative_subject()
        name.CN = hostname
        cert.set_subject(name)
        cert.set_issuer(self.cert.get_subject())
        cert.set_pubkey(key)
        notBefore = m2.x509_get_not_before(cert.x509)
        notAfter  = m2.x509_get_not_after(cert.x509)
        m2.x509_gmtime_adj(notBefore, 0)
        m2.x509_gmtime_adj(notAfter, lifetime)
        ext = X509.new_extension('basicConstraints', 'CA:FALSE')
        ext.set_critical()
        cert.add_ext(ext)
        ext = X509.new_extension('keyUsage',
                                 'digitalSignature, keyEncipherment')
        ext.set_critical()
        cert.add_ext(ext)
        cert.sign(self.key, sign_hash)
        return cert, key

    def get_relative_subject(self):
        """Return a X509_NAME wthout the CN field set suitable for a EEC signed by the CA"""
        name = X509.X509_Name()
        ca_name = self.cert.get_subject()
        name.O = "My Org"  # TODO: Make this configurable
        return name
