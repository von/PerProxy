#!/usr/bin/env python
"""Test out code by querying all notaries"""

import sys

from Notary import Notaries

def main():
    service_hostname = "encrypted.google.com"
    service_port = 443
    service_type = "ssl"
    notaries = Notaries.from_file("http_notary_list.txt")
    responses = notaries.query(service_hostname, service_port, service_type)
    valid_responses = [r for r in responses if r is not None]
    print "Got {} responses from {} notaries".format(len(valid_responses),
                                                     len(responses))
    for response in valid_responses:
        print "Response from {}:".format(response.notary)
        print response.xml

if __name__ == "__main__":
    sys.exit(main())
