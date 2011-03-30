#!/usr/bin/env python
"""Query Perspectives Notaries regarding a given server"""

import argparse
import logging
import sys

from Notary import Notaries, NotaryServiceType

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger()
    output.setLevel(logging.DEBUG)
    output_handler = logging.StreamHandler(sys.stdout)  # Default is sys.stderr
    # Set up formatter to just print message without preamble
    output_handler.setFormatter(logging.Formatter("%(message)s"))
    output.addHandler(output_handler)

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
                        type=int, default=NotaryServiceType.SSL,
                        help="specify service type", metavar="type")
    parser.add_argument('service_hostname', metavar='hostname',
                        type=str, nargs=1,
                        help='host about which to query')
    args = parser.parse_args()

    output_handler.setLevel(args.output_level)

    notaries = Notaries.from_file(args.notaries_file)
    output.debug("Read configuration for {} notaries from configuration {}".format(len(notaries), args.notaries_file))
    output.debug("Requesting information about {}:{},{} from {} notaries".format(args.service_hostname[0], args.service_port, args.service_type, args.num_notaries))
    responses = notaries.query(args.service_hostname[0],
                               args.service_port,
                               args.service_type,
                               num=args.num_notaries)
    valid_responses = [r for r in responses if r is not None]
    output.info("Got {} valid responses from {} notaries".format(len(valid_responses),
                                                                 len(responses)))
    for response in valid_responses:
        output.info(response)
    return(0)

if __name__ == "__main__":
    sys.exit(main())

