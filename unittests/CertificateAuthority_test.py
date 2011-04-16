#!/usr/bin/env python
"""Unittests for CertificateAuthority class"""

import unittest

class TestCertificateAuthority(unittest.TestCase):
    """Tests for CertificateAuthority class"""

    def _load_ca(self):
        """Load and return a test CA"""
        from CertificateAuthority import CertificateAuthority
        return CertificateAuthority.from_file("ca-cert.pem", "ca-key.pem")

    def test_from_file(self):
        """Test load_file()"""
        from CertificateAuthority import CertificateAuthority
        ca = CertificateAuthority.from_file("ca-cert.pem", "ca-key.pem")

    def test_generate_ssl_credential(self):
        """Test generate_ssl_credential()"""
        ca = self._load_ca()
        cert, key = ca.generate_ssl_credential("www.example.com")
        self.assertIsNotNone(cert)
        self.assertIsNotNone(key)
        subject = cert.get_subject().as_text()
        # XXX: This assumed hard-coded O component
        self.assertEqual(subject, "O=My Org, CN=www.example.com")
        self.assertEqual(key, ca.service_key)

if __name__ == "__main__":
    unittest.main()
