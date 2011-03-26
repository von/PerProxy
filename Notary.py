"""Class for representing Perspective Notaries"""

import re
import urllib
import xml.dom.minidom

class NotaryException(Exception):
    """Exception related to a Notary"""
    pass

class Notaries(list):
    """Class for representing the set of trusted Notaries"""

    @classmethod
    def from_file(cls, file_path):
        """Return Notaries described in file.

        See from_stream() for expected format."""
        with file(file_path, "r") as f:
            notaries = cls.from_stream(f)
        return notaries

    @classmethod
    def from_stream(cls, stream):
        """Return Notaries described in given stream.

        Expected format for each Notary is:
        # Lines starting with '#' are comments and ignored
        <hostname>:<port>
        -----BEGIN PUBLIC KEY-----
        <multiple lines of Base64-encoded data>
        -----END PUBLIC KEY----
        """
        notaries = Notaries()
        while True:
            notary = Notary.from_stream(stream)
            if notary is None:  # EOF
                break
            else:
                notaries.append(notary)
        return notaries

    def query(self, service_hostname, port, type):
        """Query all Notaries and return array of Responses.

        For any Notary not responding, a None will be in the array."""
        responses = []
        for notary in self:
            self._debug("Querying {}...".format(notary))
            try:
                response = notary.query(service_hostname,
                                        port,
                                        type)
                self._debug("Got response from {}".format(notary))
                responses.append(response)
            except Exception as e:
                self._debug("No response from {}: {}".format(notary, e))
                responses.append(None)
        return responses

    def __str__(self):
        return "[" + ",".join([str(n) for n in self]) + "]"

    def _debug(self, msg):
        print msg

class Notary:
    """Class for representing Perspective Notary"""

    # Perspective type values. Determined experimentally.
    TYPE_VALUES = {
        "https" : 2,
        "ssl" : 2,
        }

    def __init__(self, hostname, port, public_key):
        self.hostname = hostname
        self.port = port
        self.public_key = public_key

    def __str__(self):
        return "Notary at {} port {}".format(self.hostname, self.port)

    def query(self, service_hostname, port, type):
        """Query notary regarding given service, returning NotaryResponse

        type may be with numeric value or 'https'"""
        if self.TYPE_VALUES.has_key(type):
            type = self.TYPE_VALUES[type]
        url = "http://{}:{}/?host={}&port={}&service_type={}".format(self.hostname, self.port, service_hostname, port, type)
        stream = urllib.urlopen(url)
        response = "".join(stream.readlines())
        stream.close()
        return NotaryResponse(response, self, service_hostname, port, type, url)

    @classmethod
    def from_stream(cls, stream):
        """Return Notary described in given stream.

        Expected format is:
        # Lines starting with '#' are comments and ignored
        <hostname>:<port>
        -----BEGIN PUBLIC KEY-----
        <multiple lines of Base64-encoded data>
        -----END PUBLIC KEY----

        If EOF is found before a Notary, returns None.
        """
        hostname, port, public_key = None, None, None
        hostname_port_re = re.compile("(\S+):(\d+)")
        for line in stream:
            line = line.strip()
            if line.startswith("#") or (line == ""):
                continue  # Ignore comments and blank lines
            match = hostname_port_re.match(line)
            if match is not None:
                hostname = match.group(1)
                port = int(match.group(2))
            elif line == "-----BEGIN PUBLIC KEY-----":
                if hostname is None:
                    raise NotaryException("Public key found without Notary")
                public_key = cls._read_public_key_from_stream(stream)
                break  # End of Notary
            else:
                raise NotaryException("Unrecognized line: " + line)
        if hostname is None:
            # We hit EOF before finding a Notary
            return None
        if public_key is None:
            raise NotaryException("No public key found for Notary {}:{}".format(hostname, port))
        return Notary(hostname, port, public_key)

    @classmethod
    def _read_public_key_from_stream(cls, stream):
        """Read and return public key, consuming ending "END PUBLIC KEY" line"""
        pub_key = ""
        for line in stream:
            line = line.strip()
            if line == "-----END PUBLIC KEY-----":
                break
            pub_key += line
        else:
            raise NotaryException("No closing 'END PUBLIC KEY' line found")
        return pub_key

class NotaryResponseException(Exception):
    """Exception related to NotaryResponse"""
    pass

class NotaryResponse:
    """Response from a Notary"""
        
    def __init__(self, xml, notary, hostname, port, type, url):
        """Create a NotaryResponse instance"""
        self.xml = xml
        self.notary = notary
        self.hostname = hostname
        self.port = port
        self.type = type
        self.url = url
        self._parse_xml()

    def _parse_xml(self):
        """Parse self.xml setting other attributes on self"""
        self.dom = xml.dom.minidom.parseString(self.xml)
        doc_element = self.dom.documentElement.tagName
        if doc_element != "notary_reply":
            raise NotaryResponseException("Unrecognized document element: {}".format(doc_element))
        
    def __str__(self):
        return self.dom.toxml()
        
