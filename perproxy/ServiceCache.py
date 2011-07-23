"""Cache class for server certificates"""

import logging

from Perspectives import Fingerprint

def now():
    """Return current time in seconds as integer"""
    import time
    return int(time.time())

class ServiceCache:
    """Cache of server certificate fingerprints

    Fingerprints are strings in hex colon-separated word format, e.g.:
    07:ba:c7:8b:99:5d:cc:4b:2e:3c:fe:9b:a2:a3:de:2ed
    """
    def __init__(self):
        self.store = {}
        self.logger = logging.getLogger()

    def get(self, service):
        """Return Fingerprint instance and last time seen for given host

        Returns None if there is no certificate in the cache."""
        key = self._key(service)
        if not self.store.has_key(key):
            raise KeyError("Host %s port %s not in cache" % (hostname,
                                                                 port))
        values = self.store[key]
        return (Fingerprint.from_string(values[0]), values[1])

    def has_entry(self, service):
        """Return True if hostname and port are in cache, False otherwise"""
        return self.store.has_key(self._key(service))
    
    def add(self, service, fingerprint):
        """Add certificate to cache for given service"""
        key = self._key(service)
        self.logger.debug("Adding to Cache: %s -> %s" % (service,
                                                             fingerprint))
        self.store[key] = (str(fingerprint), now())

    @classmethod
    def _key(cls, service):
        """Given a hostname and port, return the key for the store"""
        return "%s:%s,%s" % (service.hostname, service.port, service.type)


        
