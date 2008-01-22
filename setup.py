# Copyright (C) 2003-2007  Robey Pointer <robey@lag.net>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.


longdesc = '''
This is a library for making SSH2 connections (client or server).
Emphasis is on using SSH2 as an alternative to SSL for making secure
connections between python scripts.  All major ciphers and hash methods
are supported.  SFTP client and server mode are both supported too.

Required packages:
    pyCrypto
'''

# if someday we want to *require* setuptools, uncomment this:
# (it will cause setuptools to be automatically downloaded)
#import ez_setup
#ez_setup.use_setuptools()

import sys
try:
    from setuptools import setup
    kw = {
        'install_requires': 'pycrypto >= 1.9',
    }
except ImportError:
    from distutils.core import setup
    kw = {}
    
if sys.platform == 'darwin':
	import setup_helper
	setup_helper.install_custom_make_tarball()


setup(name = "paramiko",
      version = "1.7.2",
      description = "SSH2 protocol library",
      author = "Robey Pointer",
      author_email = "robey@lag.net",
      url = "http://www.lag.net/paramiko/",
      packages = [ 'paramiko' ],
      download_url = 'http://www.lag.net/paramiko/download/paramiko-1.7.2.zip',
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
