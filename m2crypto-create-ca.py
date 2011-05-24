#!/usr/bin/env python
"""Create a CA key and certificate with M2Crypto"""
import argparse
import logging
import sys

from M2Crypto import EVP, m2, RSA, X509

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger(argv[0])
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
    parser.add_argument("-k", "--keylength", type=int, default=2048,
                        help="specify key length", metavar="length")
    parser.add_argument("-C", "--cn", type=str, default="PerProxy CA",
                        help="specify CommonName component", metavar="cn")
    parser.add_argument("-O", "--org", type=str, default="PerProxy",
                        help="specify Org component", metavar="org")
    parser.add_argument("-l", "--lifetime", type=int, default=365,
                        help="specify certificate lifetime in days",
                        metavar="days")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    parser.add_argument("certFile", metavar="path", type=str, nargs="?",
                        default="ca-cert.crt",
                        help="where to save PEM-encoded certificate")
    parser.add_argument("keyFile", metavar="path", type=str, nargs="?",
                        default="ca-key.pem",
                        help="where to save PEM-encoded key")
    args = parser.parse_args()
    output_handler.setLevel(args.output_level)

    output.info("Generating keys...")
    rsa_key = RSA.gen_key(args.keylength, m2.RSA_F4)
    key = EVP.PKey()
    key.assign_rsa(rsa_key)

    output.info("Generating certificate...")
    cert = X509.X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    name = X509.X509_Name()
    name.CN = args.cn
    name.O = args.org
    cert.set_subject(name)
    cert.set_issuer(name)
    cert.set_pubkey(key)
    notBefore = m2.x509_get_not_before(cert.x509)
    notAfter  = m2.x509_get_not_after(cert.x509)
    m2.x509_gmtime_adj(notBefore, 0)
    m2.x509_gmtime_adj(notAfter, args.lifetime * 60 * 60 * 24)
    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    ext.set_critical()
    cert.add_ext(ext)
    ext = X509.new_extension('keyUsage', 'digitalSignature, keyEncipherment, keyCertSign, cRLSign')
    ext.set_critical()
    cert.add_ext(ext)
    cert.sign(key, 'sha1')
    output.info("Saving certificate to {}".format(args.certFile))
    cert.save_pem(args.certFile)
    output.info("Saving private key to {}".format(args.keyFile))
    key.save_key(args.keyFile, cipher=None)  # cipher=None -> save in the clear
    output.info("Success.")

    return(0)

if __name__ == "__main__":
    sys.exit(main())
