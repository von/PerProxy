"""Interface to Perspectives logic"""

import hashlib
import logging
import ssl

from Perspectives import PerspectivesException
from Perspectives import Notaries
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
#
# Policy exceptions

class PolicyException(Exception):
    """Policy check failed"""
    pass

class QuorumNotReached(PolicyException):
    """Not enough notaries have seen given key"""
    
    def __init__(self, notaries_needed, notaries_saw_key):
        self.notaries_needed = notaries_needed
        self.notaries_saw_key = notaries_saw_key

    def __str__(self):
        return "Only %s out of required %s notaries have seen key" % (
            self.notaries_saw_key, self.notaries_needed)

class QuorumDurationNotReached(PolicyException):
    """Quorum duration not reached for given key"""

    def __init__(self, duration_needed, duration_achieved):
        self.duration_needed = duration_needed
        self.duration_achieved = duration_achieved

    def __str__(self):
        return "Quorum duration of %s shorter than required %s" % (
            self.duration_achieved, self.duration_needed)

######################################################################

class Checker:
    """Inteface to Persepectices logic"""

    def __init__(self, cache=None, notaries_file=None,
                 quorum_percentage=75, quorum_duration=86400,
                 stale_limit=86400):
        """Check a Perspectives Checker instance

        quorum_percentage is percentage of notaries needed for quorum

        quorum_duration is seconds of quorum needed

        stale_limit: any response without a seen key fresher than this
        limit is ignored inside this limit. I.e. a notary with a stale
        response does not count towards quorum inside this period.
        """
        self.logger = logging.getLogger("Perspectives.Checker")
        self.logger.debug("Perspective Checker class initializing")
        self.cache = cache if cache is not None \
            else ServiceCache()
        # Age at which entry in cache is stale and ignored
        self.cache_stale_age = 24 * 3600
        notaries_file = notaries_file if notaries_file is not None \
            else "./http_notary_list.txt"
        self.notaries = Notaries.from_file(notaries_file)
        self.quorum = int(len(self.notaries) * quorum_percentage / 100)
        self.logger.debug(
            "%d notaries, quorum is %d (%d%%)" % (len(self.notaries),
                                                  self.quorum,
                                                  quorum_percentage))
        self.quorum_duration = quorum_duration
        self.stale_limit = stale_limit
        self.logger.debug("Perspective instance initialized")

    def check_seen_fingerprint(self, service, fingerprint):
        """Check the actual server fingerprint seen.

        Raises exception on problem."""
        self.logger.debug("Checking seen fingerprint for %s: %s" % (service, fingerprint))
        cached_fingerprint = self._get_cached_fingerprint(service)
        if (cached_fingerprint is None or
            fingerprint != cached_fingerprint):
            self.logger.debug("Cache miss, checking fingerprint against policy")
            try:
                self.do_policy_check(service, fingerprint)
            except PolicyException as e:
                raise PerspectivesException("Policy check failed on %s for %s: %s" % (fingerprint, service, e))
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
                self.logger.debug("Cache hit: %s -> %s" % (service,
                                                               fingerprint))
                return fingerprint
            self.logger.debug("Cache is stale for %s" % (service))
        else:
            self.logger.debug("Cache miss for %s" % (service))
        return None

    def do_policy_check(self, service, fingerprint):
        """Check given service and certificate against Notaries with our policy

        Raises PolicyException on policy failure"""
        self.logger.debug("Querying notaries regarding %s and %s" % (service, fingerprint))
        self.responses = self.notaries.query(service)
        valid_responses = [r for r in self.responses if r is not None]
        self.logger.debug("Got %s responses" % (len(valid_responses)))
        agree_now = self.responses.key_agreement_count(fingerprint)
        self.logger.debug("%d notaries agree on key now" % agree_now)
        if agree_now < self.quorum:
            self.logger.debug("Quorum failed at current time")
            raise QuorumNotReached(self.quorum, agree_now)
        qduration = self.responses.quorum_duration(fingerprint,
                                                   self.quorum,
                                                   self.stale_limit)
        self.logger.debug("Quorum duration is %s" % (qduration))
        if qduration < self.quorum_duration:
            raise QuorumDurationNotReached(self.quorum_duration, qduration)
        self.logger.debug("Policy check succeeded %s" % (qduration))
