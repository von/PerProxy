# Make these classes available via 'from Perspectives import ...'
from Checker import Checker
from Exceptions import PerspectivesException
from Exceptions import FingerprintException
from Exceptions import NotaryException
from Exceptions import NotaryResponseException
from Exceptions import NotaryUnknownServiceException
from Exceptions import NotaryResponseBadSignature
from Fingerprint import Fingerprint
from Notary import Notary, Notaries
from Notary import NotaryResponse, NotaryResponses
from Notary import NotaryResponseBadSignature
from Notary import ServiceKey
from Service import Service, ServiceType

# Avoid warnings about lack of defined handlers
# http://docs.python.org/howto/logging.html#library-config
import logging

# NullHandler not in Python < 2.7
class NullHandler(logging.Handler):
    def emit(self, record):
        pass

logging.getLogger("Perspectives").addHandler(NullHandler())
