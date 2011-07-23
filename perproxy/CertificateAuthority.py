"""Certificate Authority"""

from M2Crypto import EVP, m2, RSA, X509
from threading import Lock
import os
import tempfile
import time

class CertificateAuthority:
    """A CA optimized for a SSL MITM proxy.

    It is thread-safe and uses the same RSA key for all service certificates
    (to save time generating RSA keys)."""

    def __init__(self, cert, key,
                 serial_number = None,
                 service_key_length=2048):
        self.cert = cert
        self.key = key
        self.serial_number = serial_number \
            if serial_number is not None else int(time.time())
        self.serial_number_lock = Lock()
        def null_callback(p,n):
            """Call back that does nothing to avoid printing to stdout"""
            pass
        # Key to use for all service certificates
        rsa_key = RSA.gen_key(service_key_length, m2.RSA_F4,
                              callback=null_callback)
        self.service_key = EVP.PKey()
        self.service_key.assign_rsa(rsa_key)

    @classmethod
    def from_file(cls, cert_file, key_file):
        cert = X509.load_cert(cert_file)
        key = EVP.load_key(key_file)
        return cls(cert, key)

    def get_ssl_credentials(self,
                            hostname,
                            lifetime=24*60*60,
                            sign_hash="sha1"):
        """Get the SSL credentials for mimicing the given host in files."""
        cert, key = self.generate_ssl_credential(hostname,
                                                 lifetime=lifetime,
                                                 sign_hash=sign_hash)
        fd, cert_file = tempfile.mkstemp()
        os.close(fd)
        cert.save_pem(cert_file)
        fd, key_file = tempfile.mkstemp()
        os.close(fd)
        key.save_key(key_file, cipher=None)  # cipher=None -> save in the clear
        return cert_file, key_file

    def generate_ssl_credential(self,
                                hostname,
                                
                                lifetime=24*60*60,
                                sign_hash="sha1"):
        """Generate credentials for a given target.

        Returns a tuple of X509 certificate and EVP key."""
        cert = X509.X509()
        cert.set_serial_number(self._get_next_serial_number())
        cert.set_version(2)
        name = self.get_relative_subject()
        name.CN = hostname
        cert.set_subject(name)
        cert.set_issuer(self.cert.get_subject())
        cert.set_pubkey(self.service_key)
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
        return cert, self.service_key

    def get_relative_subject(self):
        """Return a X509_NAME wthout the CN field set suitable for a EEC signed by the CA"""
        name = X509.X509_Name()
        ca_name = self.cert.get_subject()
        name.O = "My Org"  # TODO: Make this configurable
        return name

    def _get_next_serial_number(self):
        """Get next serial number to use in thread-safe manner"""
        with self.serial_number_lock:
            self.serial_number += 1
            next_serial_number = self.serial_number
        return next_serial_number
