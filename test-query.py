#!/usr/bin/env python
"""Test out code by querying all notaries"""

import sys

from Notary import Notary

def main():
    service_hostname = "encrypted.google.com"
    service_port = 443
    service_type = "ssl"
    notaries = Notary.notaries_from_file("http_notary_list.txt")
    print notaries
    print notaries[1]
    for notary in notaries:
        print notary
        print "Querying {}...".format(notary)
        response = notary.query(service_hostname, service_port, service_type)
        print response

if __name__ == "__main__":
    sys.exit(main())
