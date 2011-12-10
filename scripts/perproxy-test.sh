#!/bin/sh
#
# Retrieve URL through PerProxy to test it.
#

######################################################################
# Defaults

PERPROXY_ADDRESS="http://localhost:8080"
WGET="wget"
TARGET="https://encrypted.google.com"
TIMEOUT="5"
DEBUG_MODE=0

######################################################################
#

WGET_OPTIONS=""
WGET_OPTIONS="${WGET_OPTIONS} --no-check-certificate"
#WGET_OPTIONS="${WGET_OPTIONS} --connect-timeout=${TIMEOUT}"
#WGET_OPTIONS="${WGET_OPTIONS} --read-timeout=${TIMEOUT}"
# Prevents "Error starting SSL with client: wrong version number"
WGET_OPTIONS="${WGET_OPTIONS} --secure-protocol=SSLv3"
# Discard output
WGET_OPTIONS="${WGET_OPTIONS} -O /dev/null"

######################################################################
#
# Process command line

usage()
{
echo "Usage: $0 <options> [<url>]

Options:
  -d               Turn on debugging
  -h               Print help and exit
  -p <url>         Perproxy address
"
}

while getopts "dhp:" option ; do
    case $option in
	d) DEBUG_MODE=1 ;;
	h) usage ; exit 0 ;;
	p) PERPROXY_ADDRESS=$OPT_ARG ;;
    esac
done

shift $(($OPTIND - 1))

if test $# -gt 0 ; then
    TARGET=$1
    shift
fi

if test $# -gt 0 ; then
    echo "Ignoring extra options"
fi

if test ${DEBUG_MODE} -eq 1 ; then
    WGET_OPTIONS="${WGET_OPTIONS} -v"
else
    WGET_OPTIONS="${WGET_OPTIONS} -q"
fi

echo "Retrieving ${TARGET} through ${PERPROXY_ADDRESS}"

export https_proxy=${PERPROXY_ADDRESS}

${WGET} ${WGET_OPTIONS} ${TARGET}

if test $? -ne 0 ; then
    echo "Error."
    exit 1
fi

echo "Success."

exit 0
