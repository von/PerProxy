"""Interface to Perspectives logic"""

import hashlib
import logging
import ssl

from Exceptions import PerspectivesException
from Notary import Notaries
from Policy import Policy, PolicyException
from ServiceCache import ServiceCache

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

    def __init__(self, policy=None, cache=None, notaries_file=None):
        """Check a Perspectives Checker instance"""
        self.logger = logging.getLogger("Perspectives.Checker")
        self.logger.debug("Perspective Checker class initializing")
        self.cache = cache if cache is not None \
            else ServiceCache()
        # Age at which entry in cache is stale and ignored
        self.cache_stale_age = 24 * 3600
        notaries_file = notaries_file if notaries_file is not None \
            else "./http_notary_list.txt"
        self.notaries = Notaries.from_file(notaries_file)
        # Default policy is quorum of n-1 and quorum duration of 1 day
        self.policy = policy if policy is not None \
            else Policy(quorum=len(self.notaries) - 1,
                        quorum_duration=24*3600)
        self.logger.debug("Perspective instance initialized")

    def check_seen_fingerprint(self, service, fingerprint):
        """Check the actual server fingerprint seen.

        Raises exception on problem."""
        self.logger.debug("Checking seen fingerprint for {}: {}".format(service, fingerprint))
        cached_fingerprint = self._get_cached_fingerprint(service)
        if (cached_fingerprint is None or
            fingerprint != cached_fingerprint):
            self.logger.debug("Cache miss, checking fingerprint against policy")
            try:
                self.do_policy_check(service, fingerprint)
            except PolicyException as e:
                raise PerspectivesException("Policy check failed on {} for {}: {}".format(fingerprint, service, e))
            self.logger.info("Fingerprint checked out.")
            self.cache.add(service, fingerprint)
        else:
            self.logger.info("Fingerprint matched cache")

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

    def do_policy_check(self, service, fingerprint):
        """Check given service and certificate against Notaries with our policy

        Raises PolicyException on policy failure"""
        self.logger.debug("Querying notaries regarding {} and {}".format(service, fingerprint))
        self.responses = self.notaries.query(service)
        self.logger.debug("Got {} responses".format(len(self.responses)))
        self.policy.check(fingerprint, self.responses)
