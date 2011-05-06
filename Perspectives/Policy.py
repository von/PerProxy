"""Classes for representing and implementing a Perspectives policy"""

import logging

import Notary

class PolicyException(Exception):
    """Policy check failed"""
    pass

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
        self.logger.debug("check({}) called with {} responses".format(fingerprint,
                                                                      len(responses)))
        qduration = responses.quorum_duration(fingerprint,
                                              self.quorum,
                                              self.stale_limit)
        self.logger.debug("Quorum duration is {}".format(qduration))
        if qduration == 0:
            raise PolicyException("Given key not valid")
        elif qduration < self.quorum_duration:
            raise PolicyException("Certificate not valid long enough (only {} seconds)".format(qduration))
        self.logger.debug("Policy check succeeded".format(qduration))

        
