#!/usr/bin/env python
import os.path
try:
    from setuptools import setup
except:
    from distutils.core import setup

from perproxy import DEFAULT_INSTALL_PATH, DEFAULT_USER_CONF_PATH, VERSION

# Our configuration files

CONF_PATH = os.path.join(DEFAULT_INSTALL_PATH, "etc")
CONF_FILES = [
    "conf/PerProxy.conf",
    "conf/http_notary_list.txt",
    ]

#
# Our scripts

SCRIPT_PATH = os.path.join(DEFAULT_INSTALL_PATH, "bin")
SCRIPT_FILES = [
    "scripts/PerProxy",
    "scripts/perproxy-create-ca",
]

#
# Do it

setup(
    name = "PerProxy",
    version = VERSION,
    packages = [ "perproxy" ],
    # Files in package_data must also appear in MANIFEST.in
    package_data = { "perproxy" : [
            "conf/error_template.html",
            "conf/logging.config",
            ] },
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
