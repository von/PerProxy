"""Classes for representing and implementing a Perspectives policy"""

import logging

import Notary

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

class Policy:
    """Class for representing and implementing a Perspectives policy"""

    def __init__(self, quorum, quorum_duration=0, stale_limit=24*3600):
        """Create a policy requiring the given quorum and quorum duration.

        Quorum == number of notaries that support given key.
        Quorum duration == length of time (sec) that quorum is met."""
        self.quorum = quorum
        self.quorum_duration = quorum_duration
        self.stale_limit = stale_limit
        self.logger = logging.getLogger("Perspectives.Policy")
        self.logger.debug("Initialized.")

    def check(self, fingerprint, responses, time=None):
        """Do responses satisfy polify for given certificate fingerprint at given time.

        fingerprint must be a Fingerprint instance
        responses must be a list of NotaryResponse instances.
        time is an integer expressing seconds since 1970 (None == now).

        Raises exception on failure."""
        self.logger.debug("check(%s) called with %s responses" % (fingerprint,
                                                                      len(responses)))
        agree_now = responses.key_agreement_count(fingerprint)
        if agree_now < self.quorum:
            raise QuorumNotReached(self.quorum, agree_now)
        qduration = responses.quorum_duration(fingerprint,
                                              self.quorum,
                                              self.stale_limit)
        self.logger.debug("Quorum duration is %s" % (qduration))
        if qduration < self.quorum_duration:
            raise QuorumDurationNotReached(self.quorum_duration, qduration)
        self.logger.debug("Policy check succeeded %s" % (qduration))

        
