"""Class for representing Perspective Notaries"""

import asyncore
import base64
import httplib
import logging
import M2Crypto
import random
import re
import struct
import time
import urllib
import xml.dom.minidom

from Exceptions import NotaryException
from Exceptions import NotaryResponseBadSignature
from Exceptions import NotaryResponseException
from Exceptions import NotaryUnknownServiceException
from Service import ServiceType
from Fingerprint import Fingerprint
from HTTP_dispatcher import HTTP_dispatcher


class Notaries(list):
    """Class for representing the set of trusted Notaries"""

    logger = logging.getLogger("Perspectives.Notary")

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

    def query(self, service, num=0):
        """Query Notaries and return NotaryResponses instance

        For any Notary not responding, a None will be in the array.

        num specifies the number of Notaries to query. If 0, all notaries
        are queried."""
        if num == 0:
            to_query = self
        else:
            if num > len(self):
                raise ValueError("Too many notaries requested (%s > %s)" % (num, len(self)))
            to_query = random.sample(self, num)
        responses = NotaryResponses()
        dispatchers = []
        # Use own map here for thread safety
        map = {}
        for notary in to_query:
            self.logger.debug("Querying %s about %s..." % (notary, service))
            dispatchers.append((notary,
                                HTTP_dispatcher(notary.get_url(service),
                                                map=map)))
        self.logger.debug("Calling asyncore.loop()")
        asyncore.loop(map=map)
        self.logger.debug("asyncore.loop() done.")
        for notary, dispatcher in dispatchers:
            try:
                response = dispatcher.get_response()
                xml = response.read()
                response = NotaryResponse(xml)
                self.logger.debug("Validating response from %s" % (notary))
                notary.verify_response(response, service)
                self.logger.debug("Response signature verified")
                responses.append(response)
            except httplib.BadStatusLine as e:
                self.logger.error("Failed to parse response from %s, bad status: %s" % (notary, e))
                responses.append(None)
            except NotaryException as e:
                self.logger.error("Error validating response from %s: %s" % (notary, e))
                responses.append(None)
            except Exception as e:
                self.logger.error("Unknown error handling response from %s: %s" % (notary, e))
                responses.append(None)
        return responses

    def find_notary(self, hostname, port=None):
        """Find notary inlist.

        hostname must match. If port is not None, it must match too.

        Returns None if notary is not found."""
        for notary in self:
            if notary.hostname != hostname:
                continue
            if (port is not None) and (notary.port != port):
                continue
            return notary
        # Failure
        return None

    def __str__(self):
        return "[" + ",".join([str(n) for n in self]) + "]"


class Notary:
    """Class for representing Perspective Notary"""

    def __init__(self, hostname, port, public_key):
        self.hostname = hostname
        self.port = port
        self.public_key = public_key

    def __str__(self):
        return "Notary at %s port %s" % (self.hostname, self.port)

    def query(self, service):
        """Query notary regarding given service, returning NotaryResponse

        type may be with numeric value or 'https'"""
        url = self.get_url(service)
        try:
            stream = urllib.urlopen(url)
        except IOError as e:
            raise NotaryException("Error connecting to Notary %s: %s" % (self, str(e)))
        if stream.getcode() == 404:
            raise NotaryUnknownServiceException()
        elif stream.getcode() != 200:
            raise NotaryException("Got bad http response code (%s) from %s for %s" % (stream.getcode(), self, service))
        response = "".join(stream.readlines())
        stream.close()
        return NotaryResponse(response)

    def get_url(self, service):
        """Return the URL to use to query for the given service"""
        url = "http://%s:%s/?host=%s&port=%s&service_type=%s" % (self.hostname, self.port, service.hostname, service.port, service.type)
        return url

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
            raise NotaryException("No public key found for Notary %s:%s" % (hostname, port))
        return Notary(hostname, port, public_key)

    @classmethod
    def _public_key_from_lines(cls, lines):
        """Read and return public key from lines"""
        bio = M2Crypto.BIO.MemoryBuffer("".join(lines))
        pub_key = M2Crypto.EVP.PKey()
        pub_key.assign_rsa(M2Crypto.RSA.load_pub_key_bio(bio))
        return pub_key

    def verify_response(self, response, service):
        """Verify signature of response regarding given service.

        Raise NotaryResponseBadSignature on bad signature.

        Signature is over binary block composed of:
            Service id as a string ('hostname:port,type')
            One nul byte (Not sure what this is for)
            Response binary blob -- see NotaryResponse.bytes()
            """
        data = bytearray(b"%s:%s,%s" % (service.hostname,
                                            service.port,
                                            service.type))
        # One byte of zero  - unknown what this represents
        data.append(struct.pack("B", 0))

        data.extend(response.bytes())
        
        notary_pub_key = self.public_key
        # Todo: Assuming MD5 here, should double check response.type
        notary_pub_key.reset_context(md="md5")
        notary_pub_key.verify_init()
        notary_pub_key.verify_update(data)
        result = notary_pub_key.verify_final(response.sig)
        if result == 0:
            raise NotaryResponseBadSignature("Signature verification failed")
        elif result != 1:
            raise NotaryResponseException("Error verifying signature")

class NotaryResponses(list):
    """Wrapper around a list of NotaryResponse instances"""

    logger = logging.getLogger("Perspectives.NotaryResponses")

    def quorum_duration(self, cert_fingerprint, quorum, stale_limit):
        """Return the quorum duration of the given certificate in seconds.

        Quorum duration is the length of time at least quorum Notaries
        believe the certificate was valid."""
        if quorum > len(self):
            return(0)

        # Find the response with the last seen key with the oldest
        # time that is not older than stale_limit.
        now = int(time.time())
        stale_time_cutoff = now - stale_limit
        valid_responses = [r for r in self if r is not None]
        last_seen_key_times = [r.last_key_seen().last_timestamp() for r in valid_responses]
        non_stale_response_times = filter(lambda t: t > stale_time_cutoff,
                                          last_seen_key_times)
        if len(non_stale_response_times) == 0:
            self.logger.debug("No non-stale responses")
            return(0)
        oldest_response_time = min(non_stale_response_times)
        self.logger.debug("Oldest response time is %s" % (time.ctime(oldest_response_time)))

        # Get list of all times we had a key change
        key_change_times = reduce(lambda a,b: a + b,
                                  [r.key_change_times()
                                   for r in self])
        # We ignore all key_change_times after the oldest_response_time
        key_change_times = filter(lambda t: t <= oldest_response_time,
                                  key_change_times)

        # Make list of change times go from newest to oldest
        key_change_times.sort()
        key_change_times.reverse()

        first_valid_time = None
        for change_time in key_change_times:
            self.logger.debug("Checking time %s" % (time.ctime(change_time)))
            agreement_count = self.key_agreement_count(cert_fingerprint,
                                                       change_time)
            if agreement_count >= quorum:
                first_valid_time = change_time
                self.logger.debug("Quorum made with %s notaries" % (agreement_count))
            else:
                self.logger.debug("Not enough notaries to make quorum (%s)" % (agreement_count))
                break
        if first_valid_time is None:
            return 0  # No quorum_duration
        return now - first_valid_time

    def key_agreement_count(self, cert_fingerprint, check_time=None):
        """How many notaries agree given certificate was valid at given time?

        If check_time == None, then check for last seen key."""
        count = 0
        for response in self:
            if response is not None:
                if check_time is None:
                    seen_key = response.last_key_seen()
                else:
                    seen_key = response.key_at_time(check_time)
                if (seen_key is not None) and \
                        (seen_key.fingerprint == cert_fingerprint):
                    count += 1
        return count

class NotaryResponse:
    """Response from a Notary"""
        
    def __init__(self, xml):
        """Create a NotaryResponse instance"""
        self.xml = xml
        self._parse_xml()

    def _parse_xml(self):
        """Parse self.xml setting other attributes on self"""
        self.dom = xml.dom.minidom.parseString(self.xml)
        doc_element = self.dom.documentElement
        if doc_element.tagName != "notary_reply":
            raise NotaryResponseException("Unrecognized document element: %s" % (doc_element.tagName))
        self.version = doc_element.getAttribute("version")
        self.sig_type = doc_element.getAttribute("sig_type")
        # Convert signature from base64 to raw form
        self.sig = base64.standard_b64decode(doc_element.getAttribute("sig"))
        keys = doc_element.getElementsByTagName("key")
        self.keys = [NotaryResponseKey.from_dom(key) for key in keys]

    def bytes(self):
        """Return as bytes for signature verification

        Bytes is concatenated key data in reverse order"""
        data = bytearray()
        key_data = [key.bytes() for key in self.keys]
        key_data.reverse()
        for kd in key_data:
            data.extend(kd)
        return data

    def last_key_seen(self):
        """Return most recently seen key"""
        return max(self.keys, key=lambda k: k.last_timestamp())

    def key_at_time(self, time):
        """Get key seen at time (expressed in seconds)

        Returns None if no key known at given time."""
        for key in self.keys:
            for span in key.timespans:
                if (span.start <= time) and (span.end >= time):
                    return key
        return None

    def key_change_times(self):
        """Return list of all times the key changed"""
        return reduce(lambda a,b: a + b,
                      [key.change_times() for key in self.keys])

    def __str__(self):
        s = "Notary Response Version: %s Signature type: %s\n" % (self.version,
                                                                      self.sig_type)
        s += "\tSig: %s\n" % (base64.standard_b64encode(self.sig))
        for key in self.keys:
            s += str(key)
        return s
        
class ServiceKey:
    """Representation of a service's key"""
    def __init__(self, type, fingerprint):
        """Create a instance of a service key with given type and fingerprint.

        Type is a string as returned in a Notary response.
        Fingerprint is a Fingerprint instance."""
        self.type = type
        self.fingerprint = fingerprint

    @classmethod
    def from_string(cls, type, str):
        """Create a ServiceKey instance from a string such as:
        93:cc:ed:bb:b9:84:42:fc:da:13:49:6a:89:95:50:28"""
        fingerprint = Fingerprint.from_string(str)
        return cls(type, fingerprint)

    def __eq__(self, other):
        return ((self.type == other.type) and
                (self.fingerprint == other.fingerprint))

    def __str__(self):
        s = "Fingerprint: %s type: %s\n" % (self.fingerprint, self.type)
        return s
     
class NotaryResponseKey(ServiceKey):
    """Representation of a Key in a Notary Response"""

    @classmethod
    def from_dom(cls, dom):
        """Create NotaryResponseKey from dom instance"""
        if dom.tagName != "key":
            raise NotaryResponseException("Unrecognized key element: %s" % (dom.tagName))
        type = ServiceType.from_string(dom.getAttribute("type"))
        key = cls.from_string(type, dom.getAttribute("fp"))
        key.timespans = [NotaryResponseTimeSpan(e)
                         for e in dom.getElementsByTagName("timestamp")]
        return key

    def bytes(self):
        """Return as bytes for signature verification

        Data is for each key:
            Number of timespans as 2-byte tuple
            0, 16, 3  -- I don't know what these are
            Fingerprint
            Data for each timespan
        """
        data = bytearray(struct.pack("BB",
                                     (len(self.timespans) >> 8) & 255,
                                     len(self.timespans) & 255))
        # I don't know what these three values are
        data.extend(struct.pack("BBB", 0, 16, 3))
        data.extend(self.fingerprint.data)
        data.extend(b"".join([t.bytes() for t in self.timespans]))
        return data

    def change_times(self):
        """Return an list of all timespan end times"""
        return [t.end for t in self.timespans] + [t.start for t in self.timespans]

    def last_timestamp(self):
        """Return the last time we saw this key"""
        return max([ts.end for ts in self.timespans])

    def __str__(self):
        s = ServiceKey.__str__(self)
        for t in self.timespans:
            s += str(t) + "\n"
        return s

class NotaryResponseTimeSpan:
    """Time span (Timestamp) from a Notary response"""

    def __init__(self, dom):
        """Create NoraryResponseTimeSpan from dom"""
        if dom.tagName != "timestamp":
            raise NotaryResponseException("Unrecognized timespan element: %s" % (dom.tagName))
        self.start = int(dom.getAttribute("start"))
        self.end = int(dom.getAttribute("end"))

    def bytes(self):
        """Return as bytes for signature verification

        Data is start as 4 byte value concatenated with end as 4 byte value"""
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

    def __str__(self):
        return "%s - %s" % (time.ctime(self.start), time.ctime(self.end))
