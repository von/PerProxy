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

if __name__ == "__main__":
    unittest.main()
