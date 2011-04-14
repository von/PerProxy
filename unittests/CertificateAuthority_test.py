#!/usr/bin/env python
"""Unittests for CertificateAuthority class"""

import unittest

class TestCertificateAuthority(unittest.TestCase):
    """Tests for CertificateAuthority class"""

    def test_from_file(self):
        """Test load_file()"""
        from CertificateAuthority import CertificateAuthority
        ca = CertificateAuthority.from_file("ca-cert.pem", "ca-key.pem")


if __name__ == "__main__":
    unittest.main()
