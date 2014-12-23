#!/usr/bin/env python
import os.path
try:
    from setuptools import setup
except:
    from distutils.core import setup

from perproxy import VERSION

#
# Our scripts

SCRIPTS = [
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
    scripts = SCRIPTS,
    install_requires=['pyPerspectives >= 0.5'],

    author = "Von Welch",
    author_email = "von@vwelch.com",
    description = "A Perspectives (http://perspectives-project.org/) proxy",
    license = "MIT",
    url = "https://github.com/von/PerProxy"
)
