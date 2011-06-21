"""Class representing whitelisted services not to be checked"""

import collections
import fnmatch
import logging
import re

WhiteListElement = collections.namedtuple("WhiteListElement",
                                          ["string", "re"])

class WhiteList(list):
    """White listed services"""
    
    comment_re = re.compile("^#")
    blank_line_re = re.compile("^$")

    def __init__(self):
        self.logger = logging.getLogger("WhiteList")

    @classmethod
    def from_file(cls, filename):
        """Parse a file, returning a WhiteList instance"""
        wl = WhiteList()
        logger = logging.getLogger("WhiteList")
        with open(filename) as f:
            for line in f:
                line = line.strip()
                if cls.blank_line_re.match(line) is not None:
                    continue
                if cls.comment_re.match(line) is not None:
                    continue
                logger.debug("Adding to whitelist: " + line)
                element = WhiteListElement(line,
                                           re.compile(fnmatch.translate(line)))
                wl.append(element)
        return wl

    def contains(self, server_name):
        """Is the given server_name whitelisted?"""
        for element in self:
            if element.re.match(server_name):
                self.logger.debug(
                    "Server {} matches whitelist element: {}".format(server_name,
                                                                     element.string))
                return True
        return False
