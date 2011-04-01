#!/usr/bin/env PYTHONPATH=.. python
"""Run all of our unittests"""

import argparse
import glob
import os
import os.path
import subprocess
import sys

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Argument parsing
    parser = argparse.ArgumentParser(
        description=__doc__, # printed with -h/--help
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.add_argument('tests', metavar='tests',
                        type=str, nargs='*',
                        help='Tests to run (default is all)')
    args = parser.parse_args()

    # Change to directory in which this script resides
    os.chdir(os.path.dirname(argv[0]))

    tests = args.tests if len(args.tests) != 0 else glob.glob("./*_test.py")
    return_code = 0
    for test in tests:
        print "Running {}".format(test)
        result = subprocess.call([test])
        if result != 0:
            return_code = 1
    return(return_code)

if __name__ == "__main__":
    sys.exit(main())
