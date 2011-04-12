#!/usr/bin/env python
"""Unittests for exceptions"""

import unittest

class TestExceptions(unittest.TestCase):
    """Tests for exceptions"""

    def testPerspectivesException(self):
        """Test PerspectivesException"""
        from Perspectives import PerspectivesException

if __name__ == "__main__":
    unittest.main()
