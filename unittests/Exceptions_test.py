#!/usr/bin/env python
"""Unittests for exceptions"""

import unittest

class TestExceptions(unittest.TestCase):
    """Tests for exceptions"""

    def testPerspectivesException(self):
        """Test PerspectivesException"""
        from Perspectives import PerspectivesException

    def testNotaryException(self):
        """Test NotaryException"""
        from Perspectives import NotaryException

    def testNotaryResponseException(self):
        """Test NotaryResponseBadSignature"""
        from Perspectives import NotaryResponseBadSignature

    def testNotaryUnknownServiceException(self):
        """Test NotaryUnknownServiceException"""
        from Perspectives import NotaryUnknownServiceException

    def testNotaryResponseBadSignature(self):
        """Test NotaryResponseBadSignature"""
        from Perspectives import NotaryResponseBadSignature

if __name__ == "__main__":
    unittest.main()
