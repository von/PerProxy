"""Classes for representing application services"""

class Service:
    """Representation of a application service"""

    def __init__(self, hostname, port, type=None):
        """Create a Service instance.

        If type is non, guess based on port (not actually implemented)."""
        self.hostname = hostname
        self.port = port
        self.type = type if type is not None else ServiceType.SSL

    def __str__(self):
        return "%s:%s,%s" % (self.hostname, self.port, self.type)

class ServiceType:
    """Constants for service types"""
    # Determined experimentally. I don't know where these are documented.
    HTTPS = 2
    SSL = 2

    STRINGS = {
        "ssl" : SSL
        }
    
    @classmethod
    def from_string(cls, str):
        """Return integer value from string"""
        return cls.STRINGS[str]
