#!/usr/bin/env python
"""Unittests for Notaries class"""

import unittest

class TestNotaries(unittest.TestCase):
    """Tests for Notaries class"""

    def _load_notaries(self):
        from Notary import Notaries
        return Notaries.from_file("./http_notary_list.txt")

    def test_init(self):
        """Test basic creation of Notaries class"""
        notaries = self._load_notaries()
        self.assertIsNotNone(notaries)
        self.assertEqual(len(notaries), 4)
        for notary in notaries:
            self.assertIsNotNone(notary.hostname)
            self.assertIsNotNone(notary.port)
            self.assertIsNotNone(notary.public_key)

    def test_find_notary(self):
        """Test find_notary()"""
        notaries = self._load_notaries()
        for hostname in [
            "cmu.ron.lcs.mit.edu",
            "convoke.ron.lcs.mit.edu",
            "mvn.ron.lcs.mit.edu",
            "hostway.ron.lcs.mit.edu"
            ]:
            notary = notaries.find_notary(hostname)
            self.assertIsNotNone(notary)
            self.assertEqual(notary.hostname, hostname)
        notary = notaries.find_notary("cmu.ron.lcs.mit.edu", port=8080)
        self.assertIsNotNone(notary)
        self.assertEqual(notary.hostname, "cmu.ron.lcs.mit.edu")
        # Test a failure
        notary = notaries.find_notary("does.not.exist")
        self.assertIsNone(notary)

if __name__ == "__main__":
    unittest.main()
