"""Class for representing Perspective Notaries"""

import base64
import M2Crypto
import re
import struct
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
                response.verify_signature()
                self._debug("Response signature verified")
                responses.append(response)
            except Exception as e:
                self._debug("No response from {}: {}".format(notary, e))
                responses.append(None)
                raise
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
                lines = [line + "\n"]
                for line in stream:
                    lines.append(line)
                    if line.startswith("-----END PUBLIC KEY-----"):
                        break
                else:
                    raise NotaryException("No closing 'END PUBLIC KEY' line for key found")
                public_key = cls._public_key_from_lines(lines)
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
    def _public_key_from_lines(cls, lines):
        """Read and return public key from lines"""
        bio = M2Crypto.BIO.MemoryBuffer("".join(lines))
        pub_key = M2Crypto.EVP.PKey()
        pub_key.assign_rsa(M2Crypto.RSA.load_pub_key_bio(bio))
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
        doc_element = self.dom.documentElement
        if doc_element.tagName != "notary_reply":
            raise NotaryResponseException("Unrecognized document element: {}".format(doc_element.tagName))
        self.version = doc_element.getAttribute("version")
        self.sig_type = doc_element.getAttribute("sig_type")
        # Convert signature from base64 to raw form
        self.sig = base64.standard_b64decode(doc_element.getAttribute("sig"))
        keys = doc_element.getElementsByTagName("key")
        self.keys = [NotaryResponseKey(key) for key in keys]

    def verify_signature(self):
        """Verify signature on response. Raise NotaryResponseException on failure.

        Signature is done over the following binary block:
          Service id as a string
          0  -- I don't know what this is
          For each key (in reverse order):
            # of timespans as 2-byte tuple
            0, 16, 3  -- I don't know what these are
            Fingerprint
            For each timespan:
              Start as 4 byte tuple
              End as 4 byte tuple
        """
        
        data = bytearray(b"{}:{},{}".format(self.hostname, self.port, self.type))
        # One byte of zero  - unknown what this represents
        data.append(struct.pack("B", 0))

        key_data = [key.bytes() for key in self.keys]
        key_data.reverse()
        for kd in key_data:
            data.extend(kd)

        notary_pub_key = self.notary.public_key
        # Todo: Assuming MD5 here, should double check response.type
        notary_pub_key.reset_context(md="md5")
        notary_pub_key.verify_init()
        notary_pub_key.verify_update(data)
        result = notary_pub_key.verify_final(self.sig)
        if result == 0:
            raise NotaryResponseException("Signature verification failed")
        elif result != 1:
            raise NotaryResponseException("Error verifying signature")
        
    def __str__(self):
        s = "Response from {} regarding {}:{} type {}\n".format(self.notary,
                                                                self.hostname,
                                                                self.port,
                                                                self.type)
        s += "\tVersion: {} Signature type: {}\n".format(self.version,
                                                         self.sig_type)
        s += "\tSig: {}\n".format(base64.standard_b64encode(self.sig))
        for key in self.keys:
            s += str(key)
        return s
        
class NotaryResponseKey:
    """Key from a Notary response"""

    def __init__(self, dom):
        """Create NotaryResponseKey from dom"""
        if dom.tagName != "key":
            raise NotaryResponseException("Unrecognized key element: {}".format(dom.tagName))
        self.type = dom.getAttribute("type")
        # Convert fingerprint to binary
        self.fingerprint = bytearray([int(n,16) for n in dom.getAttribute("fp").split(":")])
        self.timespans = [NotaryResponseTimeSpan(e)
                          for e in dom.getElementsByTagName("timestamp")]

    def bytes(self):
        """Return as bytes for signature verification"""
        data = bytearray(struct.pack("BB",
                                     (len(self.timespans) >> 8) & 255,
                                     len(self.timespans) & 255))
        # I don't know what these three values are
        data.extend(struct.pack("BBB", 0, 16, 3))
        data.extend(self.fingerprint)
        data.extend(b"".join([t.bytes() for t in self.timespans]))
        return data

    def __str__(self):
        fp = ":".join(["{:02x}".format(n) for n in self.fingerprint])
        s = "Fingerprint: {} type: {}\n".format(fp, self.type)
        for t in self.timespans:
            s+= "\tStart: {} End: {}\n".format(t.start, t.end)
        return s

class NotaryResponseTimeSpan:
    """Time span (Timestamp) from a Notary response"""

    def __init__(self, dom):
        """Create NoraryResponseTimeSpan from dom"""
        if dom.tagName != "timestamp":
            raise NotaryResponseException("Unrecognized timespan element: {}".format(dom.tagName))
        self.start = int(dom.getAttribute("start"))
        self.end = int(dom.getAttribute("end"))

    def bytes(self):
        """Return as bytes for signature verification"""
        start_bytes = struct.pack("BBBB",
                                  (self.start >> 24) & 255,
                                  (self.start >> 16) & 255,
                                  (self.start >> 8) & 255,
                                  self.start & 255)                    
        end_bytes = struct.pack("BBBB",
                                (self.end >> 24) & 255,
                                (self.end >> 16) & 255,
                                (self.end >> 8) & 255,
                                self.end & 255)                    
        return b"".join([start_bytes, end_bytes])
