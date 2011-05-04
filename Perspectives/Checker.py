"""Interface to Perspectives logic"""

import hashlib
import logging
import ssl

from Exceptions import PerspectivesException
from Notary import Notaries
from Policy import Policy, PolicyException
from ServiceCache import ServiceCache
from TLS import Certificate

######################################################################
#
# Some helper functions

def now():
    """Return current time in seconds as integer"""
    import time
    return int(time.time())

######################################################################

class Checker:
    """Inteface to Persepectices logic"""
    def __init__(self, service):
        """Create checker for new connection"""
        self.logger.debug("New perspectives checker for {}".format(service))
        self.service = service
        self.responses = None
        self.cached_fingerprint = None
        fingerprint = self._get_cached_fingerprint(service)
        if fingerprint is None:
            # No fingerprint in cache (or was stale)
            # Get and verify cerficiate
            fingerprint = self._get_server_fingerprint(service)
            try:
                self.do_policy_check(service, fingerprint)
            except PolicyException as e:
                raise PerspectivesException("Policy check failed on {} for {}: {}".format(fingerprint, service, e))
            self.cache.add(service, fingerprint)
        self.expected_fingerprint = fingerprint

    def check_seen_fingerprint(self, fingerprint):
        """Check the actual server fingerprint seen.

        Raises exception on problem."""
        self.logger.debug("Checking seen fingerprint for {}: {}".format(self.service, fingerprint))
        if fingerprint == self.expected_fingerprint:
            self.logger.debug("Seen fingerprint matches expected")
        else:
            # XXX Check new fingerprint against policy?
            raise PerspectivesException("{}: seen fingerprint does not match expected: {} != {}".format(self.service, fingerprint, self.expected_fingerprint))
        # Success

    def _get_cached_fingerprint(self, service):
        """Get cached fingerprint, checking for freshness"""
        if self.cache.has_entry(service):
            (fingerprint, last_seen) = self.cache.get(service)
            age = now() - last_seen
            if age < self.cache_stale_age:
                self.logger.debug("Cache hit: {} -> {}".format(service,
                                                               fingerprint))
                return fingerprint
            self.logger.debug("Cache is stale for {}".format(service))
        else:
            self.logger.debug("Cache miss for {}".format(service))
        return None

    def _get_server_fingerprint(self, service):
        """Get fingerprint of certificate seen on server"""
        # XXX This assumes SSL in a big way
        self.logger.debug("Querying {} for certificate...".format(service))
        cert_pem = ssl.get_server_certificate((service.hostname, service.port))
        cert = Certificate.from_PEM(cert_pem)
        fingerprint = cert.fingerprint()
        self.logger.debug("Got certificate: {}".format(fingerprint))
        return fingerprint

    @classmethod
    def init_class(cls, policy=None, cache=None, notaries_file=None):
        """Initialize the class."""
        cls.logger = logging.getLogger()
        cls.logger.debug("Perspective class initializing")
        cls.cache = cache if cache is not None \
            else ServiceCache()
        # Age at which entry in cache is stale and ignored
        cls.cache_stale_age = 24 * 3600
        notaries_file = notaries_file if notaries_file is not None \
            else "./http_notary_list.txt"
        cls.notaries = Notaries.from_file(notaries_file)
        # Default policy is quorum of n-1 and quorum duration of 1 day
        cls.policy = policy if policy is not None \
            else Policy(quorum=len(cls.notaries) - 1,
                        quorum_duration=24*3600)
        cls.logger.debug("Perspective instance initialized")



    def do_policy_check(self, service, fingerprint):
        """Check given service and certificate against Notaries with our policy

        Raises PolicyException on policy failure"""
        self.logger.debug("Querying notaries regarding {} and {}".format(service, fingerprint))
        self.responses = self.notaries.query(service)
        self.logger.debug("Got {} responses".format(len(self.responses)))
        self.policy.check(fingerprint, self.responses)
