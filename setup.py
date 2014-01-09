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


longdesc = '''
This is a library for making SSH2 connections (client or server).
Emphasis is on using SSH2 as an alternative to SSL for making secure
connections between python scripts.  All major ciphers and hash methods
are supported.  SFTP client and server mode are both supported too.

Required packages:
    pyCrypto

To install the `in-development version
<https://github.com/paramiko/paramiko/tarball/master#egg=paramiko-dev>`_, use
`pip install paramiko==dev`.
'''

# if someday we want to *require* setuptools, uncomment this:
# (it will cause setuptools to be automatically downloaded)
#import ez_setup
#ez_setup.use_setuptools()

import sys
try:
    from setuptools import setup
    kw = {
        'install_requires': ['pycrypto >= 2.1, != 2.4',
                             'ecdsa',
                             ],
    }
except ImportError:
    from distutils.core import setup
    kw = {}

if sys.platform == 'darwin':
    import setup_helper
    setup_helper.install_custom_make_tarball()


setup(name = "paramiko",
      version = "1.12.1",
      description = "SSH2 protocol library",
      author = "Jeff Forcier",
      author_email = "jeff@bitprophet.org",
      url = "https://github.com/paramiko/paramiko/",
      packages = [ 'paramiko' ],
      license = 'LGPL',
      platforms = 'Posix; MacOS X; Windows',
      classifiers = [ 'Development Status :: 5 - Production/Stable',
                      'Intended Audience :: Developers',
                      'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
                      'Operating System :: OS Independent',
                      'Topic :: Internet',
                      'Topic :: Security :: Cryptography' ],
      long_description = longdesc,
      **kw
      )
