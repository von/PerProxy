#!/usr/bin/env python
"""Query Perspectives Notaries regarding a given server"""

import argparse
import logging
import sys

from Perspectives import Checker, Fingerprint, \
    PerspectivesException, Notaries, \
    Service, ServiceType

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger("main")
    output.setLevel(logging.DEBUG)
    output_handler = logging.StreamHandler(sys.stdout)  # Default is sys.stderr
    # Set up formatter to just print message without preamble
    output_handler.setFormatter(logging.Formatter("%(message)s"))
    output.addHandler(output_handler)

    # Set up logging for Perspectives code as well
    perspectives_logger = logging.getLogger("Perspectives")
    perspectives_logger.setLevel(logging.DEBUG)
    perspectives_logger.addHandler(output_handler)

    # Argument parsing
    parser = argparse.ArgumentParser(
        description=__doc__, # printed with -h/--help
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
    # Only allow one of debug/quiet mode
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-d", "--debug",
                                 action='store_const', const=logging.DEBUG,
                                 dest="output_level", default=logging.INFO,
                                 help="print debugging")
    verbosity_group.add_argument("-q", "--quiet",
                                 action="store_const", const=logging.WARNING,
                                 dest="output_level",
                                 help="run quietly")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    parser.add_argument("-n", "--num_notaries",
                        type=int, default=0,
                        help="specify number of notaries to query (0=All)",
                        metavar="num")
    parser.add_argument("-N", "--notaries-file",
                        type=str, default="./http_notary_list.txt",
                        help="specify notaries file", metavar="filename")
    parser.add_argument("-p", "--port", dest="service_port",
                        type=int, default=443,
                        help="specify service port", metavar="port")
    parser.add_argument("-t", "--type", dest="service_type",
                        type=int, default=ServiceType.SSL,
                        help="specify service type", metavar="type")
    parser.add_argument("-x", "--xml",
                        dest="output_xml", action="store_const", const=True,
                        default=False,
                        help="output raw XML")
    parser.add_argument('service_hostname', metavar='hostname',
                        type=str, nargs=1,
                        help='host about which to query')
    parser.add_argument('service_fingerprint', metavar='fingerprint',
                        type=str, nargs='?', default=None,
                        help='test fingerprint against responses')
    args = parser.parse_args()

    output_handler.setLevel(args.output_level)

    service = Service(args.service_hostname[0],
                      args.service_port,
                      args.service_type)

    if args.service_fingerprint is not None:
        output.debug("Checking provided fingerprint against responses...")
        checker = Checker(notaries_file=args.notaries_file)
        fp = Fingerprint.from_string(args.service_fingerprint)
        checker.check_seen_fingerprint(service, fp)
        output.debug("Check successful.")
        responses = checker.responses
    else:
        notaries = Notaries.from_file(args.notaries_file)
        output.debug("Read configuration for %s notaries from configuration %s" % (len(notaries), args.notaries_file))
        responses = notaries.query(service, num=args.num_notaries)
        if responses and len(responses):
            for response in responses:
                if args.output_xml:
                    output.info(response.xml)
                else:
                    output.info(response)
        else:
            output.info("Failed to obtain any responses")

    
    return(0)

if __name__ == "__main__":
    sys.exit(main())

