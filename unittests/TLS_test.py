#!/usr/bin/env python
"""Unittests for TLS classes"""

import unittest

class TestDecodeLength(unittest.TestCase):
    """Tests for decode_length()"""

    def test_decode_length(self):
        """Test decode_length()"""
        from TLS import decode_length
        bytes = bytearray([0x07,0x65,0xA8])
        len = decode_length(bytes)
        self.assertIsNotNone(len)
        self.assertEqual(len, 0x0765A8)

    def test_docode_length_memoryview(self):
        """Test decoe_length() with memoryview"""
        from TLS import decode_length
        bytes = bytearray([0x53,0x01])
        len = decode_length(memoryview(bytes))
        self.assertIsNotNone(len)
        self.assertEqual(len, 0x5301)

class TestCertificate(unittest.TestCase):
    """Tests for Certificae object"""
    
    @classmethod
    def _load_test_cert(cls):
        """Load and return a test certificate"""
        from TLS import Certificate
        with open("google.pem") as f:
            cert = Certificate.from_PEM("".join(f.readlines()))
        return cert

    def test_Certificate_Fingerprint(self):
        """Test loading a certificate and generating a Fingerprint"""
        cert = self._load_test_cert()
        self.assertIsNotNone(cert)
        fingerprint = cert.fingerprint()
        self.assertIsNotNone(fingerprint)
        self.assertEqual(str(fingerprint),
                         "ef:e3:e8:f4:c4:37:8a:5c:c6:6b:b5:b4:2e:dc:f2:06")

class TestFingerprint(unittest.TestCase):
    """Tests for Fingerprint object"""

    def test_equality(self):
        """Test equality methods"""
        from TLS import Fingerprint
        fp1 = Fingerprint.from_string("ef:e3:e8:f4:c4:37:8a:5c:c6:6b:b5:b4:2e:dc:f2:06")
        self.assertIsNotNone(fp1)
        fp2 = Fingerprint.from_string("ef:e3:e8:f4:c4:37:8a:5c:c6:6b:b5:b4:2e:dc:f2:06")  # Same as fp1 
        self.assertIsNotNone(fp2)
        fp3 = Fingerprint.from_string("aa:bb:e8:f4:c4:37:8a:5c:c6:6b:b5:b4:2e:dc:f2:06")  # Different from fp1
        self.assertIsNotNone(fp3)
        self.assertEqual(fp1, f2)
        self.assertNotEqual(fp1, fp3)
        self.assertNotEqual(fp2, fp3)

if __name__ == "__main__":
    unittest.main()
