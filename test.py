#!/usr/bin/python

# Copyright (C) 2003-2004 Robey Pointer <robey@lag.net>
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

"""
do the unit tests!
"""

import sys, os, unittest
from optparse import OptionParser
import paramiko

sys.path.append('tests/')

from test_message import MessageTest
from test_file import BufferedFileTest
from test_pkey import KeyTest
from test_kex import KexTest
from test_transport import TransportTest
from test_sftp import SFTPTest

default_host = 'localhost'
default_user = os.environ.get('USER', 'nobody')
default_keyfile = os.path.join(os.environ.get('HOME', '/'), '.ssh/id_rsa')
default_passwd = None

parser = OptionParser('usage: %prog [options]')
parser.add_option('--sftp', action='store_true', dest='use_sftp', default=False,
                  help='run sftp tests (currently require an external sftp server)')
parser.add_option('-H', '--sftp-host', dest='hostname', type='string', default=default_host,
                  metavar='<host>',
                  help='remote host for sftp tests (default: %s)' % default_host)
parser.add_option('-U', '--sftp-user', dest='username', type='string', default=default_user,
                  metavar='<username>',
                  help='username for sftp tests (default: %s)' % default_user)
parser.add_option('-K', '--sftp-key', dest='keyfile', type='string', default=default_keyfile,
                  metavar='<keyfile>',
                  help='location of private key for sftp tests (default: %s)' % default_keyfile)
parser.add_option('-P', '--sftp-passwd', dest='password', type='string', default=default_passwd,
                  metavar='<password>',
                  help='(optional) password to unlock the private key for sftp tests')
parser.add_option('--no-pkey', action='store_false', dest='use_pkey', default=True,
                  help='skip RSA/DSS private key tests (which can take a while)')

options, args = parser.parse_args()
if len(args) > 0:
    parser.error('unknown argument(s)')

if options.use_sftp:
    SFTPTest.init(options.hostname, options.username, options.keyfile, options.password)

# setup logging
paramiko.util.log_to_file('test.log')
    
suite = unittest.TestSuite()
suite.addTest(unittest.makeSuite(MessageTest))
suite.addTest(unittest.makeSuite(BufferedFileTest))
if options.use_pkey:
    suite.addTest(unittest.makeSuite(KeyTest))
suite.addTest(unittest.makeSuite(KexTest))
suite.addTest(unittest.makeSuite(TransportTest))
if options.use_sftp:
    suite.addTest(unittest.makeSuite(SFTPTest))
unittest.TextTestRunner(verbosity=2).run(suite)
