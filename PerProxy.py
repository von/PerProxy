#!/usr/bin/env python

import M2Crypto

import argparse
import ConfigParser
import logging
import logging.config
import os.path
import sys
import threading
import time

from perproxy import CertificateAuthority
from perproxy import Checker
from perproxy import ProxyServer, Handler
from perproxy import WhiteList


def parse_args(argv):
    """Parse our command line arguments"""
    # Parse any conf_file specification
    # We make this parser with add_help=False so that
    # it doesn't parse -h and print help.
    conf_parser = argparse.ArgumentParser(
        # Turn off help, so we print all options in response to -h
        add_help=False
        )
    conf_parser.add_argument("-c", "--conf_file",
                        help="Specify config file", metavar="FILE")
    args, remaining_argv = conf_parser.parse_known_args(argv[1:])
    defaults = {
        "ca_cert_file" : "./ca-cert.crt",
        "ca_key_file" : "./ca-key.pem",
        "error_template" : "./error_template.html",
        "logging_config" : "./logging.config",
        "notaries_file" : "./http_notary_list.txt",
        "perspectives_quorum_duration" : 86400,  # One day
        "perspectives_quorum_percentage" : 75,
        "proxy_hostname" : "localhost",
        "proxy_port" : 8080,
        "whitelist_filename" : None,
        }
    if args.conf_file:
        # Mappings from configuraition file to options
        conf_mappings = [
            # ((section, option), option)
            (("CA", "CertFile"), "ca_cert_file"),
            (("CA", "KeyFile"), "ca_key_file"),
            (("Logging", "Config"), "logging_config"),
            (("Perspectives", "NotaryFile"), "notaries_file"),
            (("Perspectives", "QuorumDuration"),
             "perspectives_quorum_duration"),
            (("Perspectives", "QuorumPercentage"),
             "perspectives_quorum_percentage"),
            (("Proxy", "Hostname"), "proxy_hostname"),
            (("Proxy", "Port"), "proxy_port"),
            (("Templates", "Error"), "error_template"),
            (("Whitelist", "Filename"), "whitelist_filename"),
            ]
        config = ConfigParser.SafeConfigParser()
        config.read([args.conf_file])
        for sec_opt, option in conf_mappings:
            if config.has_option(*sec_opt):
                value = config.get(*sec_opt)
                defaults[option] = value

    # Parse rest of arguments
    # Don't surpress add_help here so it will handle -h
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        parents=[conf_parser],
        # print script description with -h/--help
        description=__doc__,
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.set_defaults(**defaults)
    parser.add_argument("-C", "--ca-cert-file",
                        type=str,
                        help="specify CA cert file", metavar="filename")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="debug mode")
    parser.add_argument("-K", "--ca-key-file",
                        type=str,
                        help="specify CA key file", metavar="filename")
    parser.add_argument("-N", "--notaries-file",
                        type=str,
                        help="specify notaries file", metavar="filename")
    parser.add_argument("-p", "--port", dest="proxy_port",
                        type=int,
                        help="specify service port", metavar="port")
    parser.add_argument("-w", "--whitelist", dest="whitelist_filename",
                        type=str, help="specify whitelist file",
                        metavar="filename")
    args = parser.parse_args(remaining_argv)
    return args

def setup_logging(args):
    """Set up logigng via logging module"""
    if not os.path.exists(args.logging_config):
        raise ValueError("Logging configuration file %s does not exist" % (args.logging_config))
    try:
        logging.config.fileConfig(args.logging_config)
    except ConfigParser.Error as e:
        raise Exception("Error parsing logging configuration file %s: %s" % (args.logging_config, str(e)))
    if args.debug:
        # Set up exact output handler to send all logs to Stdout
        root_logger = logging.getLogger()
        root_handler = logging.StreamHandler(sys.stdout)
        root_handler.setFormatter(logging.Formatter("PerProxy: %(message)s"))
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(root_handler)

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv
 
    args = parse_args(argv)

    try:
        setup_logging(args)
    except Exception as e:
        print str(e)
        return(1)

    output = logging.getLogger("main")

    if args.debug:
        output.debug("Running in DEBUG mode")

    if args.conf_file:
        output.debug("Using configuration from %s" % (args.conf_file))

    output.debug("Initializing Perspectives checker with notaries from %s" % (args.notaries_file))

    output.debug("Loading CA from %s and %s" % (args.ca_cert_file,
                                                    args.ca_key_file))
    Handler.ca = CertificateAuthority.from_file(args.ca_cert_file,
                                                args.ca_key_file)
    Handler.checker = Checker(
        notaries_file = args.notaries_file,
        quorum_percentage=args.perspectives_quorum_percentage,
        quorum_duration=args.perspectives_quorum_duration
        )

    if args.whitelist_filename is not None:
        output.debug("Loading whitelist from %s" % (args.whitelist_filename))
        wl = WhiteList.from_file(args.whitelist_filename)
        Handler.whitelist = wl

    output.debug("Loading error template from %s" % (args.error_template))

    with open(args.error_template) as f:
        Handler.HTML_ERROR_TEMPLATE = "".join(f.readlines())

    # Per M2Crypto FAQ
    output.debug("Initializing M2Crypto threading")
    M2Crypto.threading.init()

    output.info("Starting proxy on %s port %s" % (args.proxy_hostname,
                                                      args.proxy_port))
    server = ProxyServer((args.proxy_hostname, args.proxy_port), Handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.setDaemon(True)
    server_thread.start()
    output.info("Server thread started")

    while True:
        try:
            time.sleep(100)
        except KeyboardInterrupt as e:
            output.info("Caught keyboard interrupt.")
            break

    output.debug("Cleaning up.")
    M2Crypto.threading.cleanup()
    output.debug("Exiting.")
    return(0)

if __name__ == '__main__':
    sys.exit(main())
