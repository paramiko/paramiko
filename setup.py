# Copyright (C) 2003-2008  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA.

import sys
from setuptools import setup

if sys.platform == "darwin":
    import setup_helper

    setup_helper.install_custom_make_tarball()

longdesc = """
This is a library for making SSH2 connections (client or server).
Emphasis is on using SSH2 as an alternative to SSL for making secure
connections between python scripts.  All major ciphers and hash methods
are supported.  SFTP client and server mode are both supported too.

To install the development version, ``pip install -e
git+https://github.com/paramiko/paramiko/#egg=paramiko``.
"""


# Version info -- read without importing
_locals = {}
with open("paramiko/_version.py") as fp:
    exec(fp.read(), None, _locals)
version = _locals["__version__"]

# Have to build extras_require dynamically because it doesn't allow
# self-referencing and I hate repeating myself.
extras_require = {
    "gssapi": [
        "pyasn1>=0.1.7",
        'gssapi>=1.4.1;platform_system!="Windows"',
        'pywin32>=2.1.8;platform_system=="Windows"',
    ],
    "ed25519": ["pynacl>=1.0.1", "bcrypt>=3.1.3"],
    "invoke": ["invoke>=1.3"],
}
everything = []
for subdeps in extras_require.values():
    everything.extend(subdeps)
extras_require["all"] = everything

setup(
    name="paramiko",
    version=version,
    description="SSH2 protocol library",
    long_description=longdesc,
    author="Jeff Forcier",
    author_email="jeff@bitprophet.org",
    url="https://github.com/paramiko/paramiko/",
    packages=["paramiko"],
    license="LGPL",
    platforms="Posix; MacOS X; Windows",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: "
        "GNU Library or Lesser General Public License (LGPL)",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    # TODO 3.0: remove bcrypt, pynacl and update installation docs noting that
    # use of the extras_require(s) is now required for those
    install_requires=["bcrypt>=3.1.3", "cryptography>=3.3.2", "pynacl>=1.0.1"],
    extras_require=extras_require,
)
