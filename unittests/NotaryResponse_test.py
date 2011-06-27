#!/usr/bin/env python
"""Unittests for NotaryResponse class"""

import unittest

class TestNotaryResponse(unittest.TestCase):
    """Tests for NotaryResponse class"""

    def _load_response(self, filename):
        """Load response from given filename and return"""
        from Perspectives import NotaryResponse
        with open(filename) as f:
            response = NotaryResponse("".join(f.readlines()))
        return response

    def _load_responses(self):
        """Load all responses and return NotariesResponses instance"""
        from Perspectives import NotaryResponses
        responses = NotaryResponses()
        for filename in [
            "response.1",
            "response.2",
            "response.3",
            "response.4"
            ]:
            responses.append(self._load_response(filename))
        return responses

    def _load_notaries(self):
        """Load notaries and return Notaries instance"""
        from Perspectives import Notaries
        return Notaries.from_file("./http_notary_list.txt")
        
    def test_basic(self):
        """Test basic NotaryResponse and NotaryResponses creation"""
        responses = self._load_responses()
        self.assertIsNotNone(responses)
        self.assertEqual(len(responses), 4)
        for response in responses:
            self.assertIsNotNone(response.xml)
            self.assertIsNotNone(response.bytes())
            self.assertIsNotNone(response.last_key_seen())
            self.assertIsNotNone(response.key_change_times())

    def test_response_verify(self):
        """Test verification of response"""
        from Perspectives import NotaryResponseBadSignature
        from Perspectives import Service, ServiceType
        response = self._load_response("response.1")
        self.assertIsNotNone(response)
        notaries = self._load_notaries()
        notary = notaries.find_notary("cmu.ron.lcs.mit.edu")
        notary.verify_response(response,
                               Service("www.citibank.com",
                                       443,
                                       ServiceType.SSL))

    def test_response_verify_failure(self):
        """Test verification of response"""
        from Perspectives import NotaryResponseBadSignature
        from Perspectives import Service, ServiceType
        response = self._load_response("response-bad.1")
        self.assertIsNotNone(response)
        self.assertIsNotNone(response)
        notaries = self._load_notaries()
        notary = notaries.find_notary("cmu.ron.lcs.mit.edu")
        with self.assertRaises(NotaryResponseBadSignature):
            notary.verify_response(response,
                                   Service("www.citibank.com",
                                           443,
                                           ServiceType.SSL))

    def test_last_key_seen(self):
        """Test last_key_seen()"""
        from Perspectives import ServiceKey
        from Perspectives import ServiceType
        response = self._load_response("response.1")
        key = response.last_key_seen()
        expected_key = ServiceKey.from_string(ServiceType.SSL,
                                              "87:71:5c:d4:7b:66:fd:9f:96:79:ba:0f:3e:15:b7:e3")                                  
        self.assertEqual(key, expected_key,
                         "%s != %s" % (key, expected_key))

if __name__ == "__main__":
    unittest.main()
