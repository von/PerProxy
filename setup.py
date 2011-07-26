#!/usr/bin/env python
import os.path
from setuptools import setup, find_packages

from perproxy import DEFAULT_INSTALL_PATH, DEFAULT_USER_CONF_PATH, VERSION

# Our configuration files

CONF_PATH = os.path.join(DEFAULT_INSTALL_PATH, "etc")
CONF_FILES = [
    "PerProxy-whitelist.txt",
    "PerProxy.conf",
    "error_template.html",
    "logging.config",
    ]

#
# Our scripts

SCRIPT_PATH = os.path.join(DEFAULT_INSTALL_PATH, "bin")
SCRIPT_FILES = [
    "PerProxy.py",
    "perproxy-create-ca.py",
]

#
# Do it

setup(
    name = "PerProxy",
    version = VERSION,
    packages = [ "perproxy" ],
    data_files = [
        (CONF_PATH, CONF_FILES),
        (SCRIPT_PATH, SCRIPT_FILES),
        ],

    author = "Von Welch",
    author_email = "von@vwelch.com",
    description = "A Perspectives (http://perspectives-project.org/) proxy",
    license = "MIT",
    url = "https://github.com/von/PerProxy"
)
