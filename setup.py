from distutils.core import setup

longdesc = '''
This is a library for making SSH2 connections (client or server).
Emphasis is on using SSH2 as an alternative to SSL for making secure
connections between pyton scripts.  All major ciphers and hash methods
are supported.

(Previous name: secsh)

Required packages:
    pyCrypto
'''

setup(name = "paramiko",
      version = "0.1-charmander",
      description = "SSH2 protocol library",
      author = "Robey Pointer",
      author_email = "robey@lag.net",
      url = "http://www.lag.net/~robey/paramiko/",
      py_modules = [ 'paramiko', 'transport', 'auth_transport', 'channel',
                     'message', 'util', 'ber', 'kex_group1', 'kex_gex',
                     'rsakey', 'dsskey' ],
      download_url = 'http://www.lag.net/~robey/paramiko/paramiko-0.1-charmander.zip',
      license = 'LGPL',
      platforms = 'Posix; MacOS X; Windows',
      classifiers = [ 'Development Status :: 3 - Alpha',
                      'Intended Audience :: Developers',
                      'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
                      'Operating System :: OS Independent',
                      'Topic :: Internet',
                      'Topic :: Security :: Cryptography' ],
      long_description = longdesc,
      )
