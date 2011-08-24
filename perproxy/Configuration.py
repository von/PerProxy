"""Configuration interface for PerProxy module"""

import logging

from ProxyClient import ProxyClient
from ProxyServer import ProxyServerTLSContextFactory

class Configuration:
    """Allow for configuration of PerProxy module.

    Currently supports the following values:

    CA - CertificateAuthority instance to use
    Checker - Checker instance to use
    WhiteList - WhiteList instance to use"""

    def __init__(self):
        self._logger = self.__getLogger()
        self._values = {
            "CA" : None,
            "Checker" : None,
            "WhiteList" : None, 
            }

    __logger = None

    @classmethod
    def __getLogger(cls):
        """Return our logger instance"""
        if cls.__logger is None:
            cls.__logger = logging.getLogger(cls.__name__)
        return cls.__logger

    def __getitem__(self, name):
        return self._values[name]

    def __setitem__(self, name, value):
        if not self._values.has_key(name):
            raise KeyError("Unrecognized configuration value \"%s\"" % name)
        self._logger.debug("Setting %s" % name)
        self._values[name] = value
