#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
do the unit tests!
"""

import os
import re
import sys
import unittest
from optparse import OptionParser
import paramiko
import threading
from paramiko.py3compat import PY2

sys.path.append('tests')

from tests.test_message import MessageTest
from tests.test_file import BufferedFileTest
from tests.test_buffered_pipe import BufferedPipeTest
from tests.test_util import UtilTest
from tests.test_hostkeys import HostKeysTest
from tests.test_pkey import KeyTest
from tests.test_kex import KexTest
from tests.test_packetizer import PacketizerTest
from tests.test_auth import AuthTest
from tests.test_transport import TransportTest
from tests.test_client import SSHClientTest
from test_client import SSHClientTest
from test_gssapi import GSSAPITest
from test_ssh_gss import GSSAuthTest
from test_kex_gss import GSSKexTest

default_host = 'localhost'
default_user = os.environ.get('USER', 'nobody')
default_keyfile = os.path.join(os.environ.get('HOME', '/'), '.ssh/id_rsa')
default_passwd = None


def iter_suite_tests(suite):
    """Return all tests in a suite, recursing through nested suites"""
    for item in suite._tests:
        if isinstance(item, unittest.TestCase):
            yield item
        elif isinstance(item, unittest.TestSuite):
            for r in iter_suite_tests(item):
                yield r
        else:
            raise Exception('unknown object %r inside test suite %r'
                            % (item, suite))


def filter_suite_by_re(suite, pattern):
    result = unittest.TestSuite()
    filter_re = re.compile(pattern)
    for test in iter_suite_tests(suite):
        if filter_re.search(test.id()):
            result.addTest(test)
    return result


def main():
    parser = OptionParser('usage: %prog [options]')
    parser.add_option('--verbose', action='store_true', dest='verbose', default=False,
                      help='verbose display (one line per test)')
    parser.add_option('--no-pkey', action='store_false', dest='use_pkey', default=True,
                      help='skip RSA/DSS private key tests (which can take a while)')
    parser.add_option('--no-transport', action='store_false', dest='use_transport', default=True,
                      help='skip transport tests (which can take a while)')
    parser.add_option('--no-sftp', action='store_false', dest='use_sftp', default=True,
                      help='skip SFTP client/server tests, which can be slow')
    parser.add_option('--no-big-file', action='store_false', dest='use_big_file', default=True,
                      help='skip big file SFTP tests, which are slow as molasses')
    parser.add_option('--gssapi-test', action='store_true', dest='gssapi_test', default=False,
                      help='Test the used APIs for GSS-API / SSPI authentication')
    parser.add_option('--test-gssauth', action='store_true', dest='test_gssauth', default=False,
                      help='Test GSS-API / SSPI authentication for SSHv2. To test this, you need kerberos a infrastructure.\
                      Note: Paramiko needs access to your krb5.keytab file. Make it readable for Paramiko or\
                      copy the used key to another file and set the environment variable KRB5_KTNAME to this file.')
    parser.add_option('--test-gssapi-keyex', action='store_true', dest='test_gsskex', default=False,
                      help='Test GSS-API / SSPI authenticated iffie-Hellman Key Exchange and user\
                      authentication. To test this, you need kerberos a infrastructure.\
                      Note: Paramiko needs access to your krb5.keytab file. Make it readable for Paramiko or\
                      copy the used key to another file and set the environment variable KRB5_KTNAME to this file.')
    parser.add_option('-R', action='store_false', dest='use_loopback_sftp', default=True,
                      help='perform SFTP tests against a remote server (by default, SFTP tests ' +
                      'are done through a loopback socket)')
    parser.add_option('-H', '--sftp-host', dest='hostname', type='string', default=default_host,
                      metavar='<host>',
                      help='[with -R] host for remote sftp tests (default: %s)' % default_host)
    parser.add_option('-U', '--sftp-user', dest='username', type='string', default=default_user,
                      metavar='<username>',
                      help='[with -R] username for remote sftp tests (default: %s)' % default_user)
    parser.add_option('-K', '--sftp-key', dest='keyfile', type='string', default=default_keyfile,
                      metavar='<keyfile>',
                      help='[with -R] location of private key for remote sftp tests (default: %s)' %
                      default_keyfile)
    parser.add_option('-P', '--sftp-passwd', dest='password', type='string', default=default_passwd,
                      metavar='<password>',
                      help='[with -R] (optional) password to unlock the private key for remote sftp tests')
    parser.add_option('--krb5_principal', dest='krb5_principal', type='string',
                      metavar='<krb5_principal>',
                      help='The krb5 principal (your username) for GSS-API / SSPI authentication')
    parser.add_option('--targ_name', dest='targ_name', type='string',
                      metavar='<targ_name>',
                      help='Target name for GSS-API / SSPI authentication.\
                      This is the hosts name you are running the test on in the kerberos database.')
    parser.add_option('--server_mode', action='store_true', dest='server_mode', default=False,
                      help='Usage with --gssapi-test. Test the available GSS-API / SSPI server mode to.\
                      Note: you need to have access to the kerberos keytab file.')

    options, args = parser.parse_args()

    # setup logging
    paramiko.util.log_to_file('test.log')

    if options.use_sftp:
        from tests.test_sftp import SFTPTest
        if options.use_loopback_sftp:
            SFTPTest.init_loopback()
        else:
            SFTPTest.init(options.hostname, options.username, options.keyfile, options.password)
        if not options.use_big_file:
            SFTPTest.set_big_file_test(False)
    if options.use_big_file:
        from tests.test_sftp_big import BigSFTPTest

    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(MessageTest))
    suite.addTest(unittest.makeSuite(BufferedFileTest))
    suite.addTest(unittest.makeSuite(BufferedPipeTest))
    suite.addTest(unittest.makeSuite(UtilTest))
    suite.addTest(unittest.makeSuite(HostKeysTest))
    if options.use_pkey:
        suite.addTest(unittest.makeSuite(KeyTest))
    suite.addTest(unittest.makeSuite(KexTest))
    suite.addTest(unittest.makeSuite(PacketizerTest))
    if options.use_transport:
        suite.addTest(unittest.makeSuite(AuthTest))
        suite.addTest(unittest.makeSuite(TransportTest))
    suite.addTest(unittest.makeSuite(SSHClientTest))
    if options.use_sftp:
        suite.addTest(unittest.makeSuite(SFTPTest))
    if options.use_big_file:
        suite.addTest(unittest.makeSuite(BigSFTPTest))
    if options.gssapi_test:
        GSSAPITest.init(options.targ_name, options.server_mode)
        suite.addTest(unittest.makeSuite(GSSAPITest))
    if options.test_gssauth:
        GSSAuthTest.init(options.krb5_principal, options.targ_name)
        suite.addTest(unittest.makeSuite(GSSAuthTest))
    if options.test_gsskex:
        GSSKexTest.init(options.krb5_principal, options.targ_name)
        suite.addTest(unittest.makeSuite(GSSKexTest))
    verbosity = 1
    if options.verbose:
        verbosity = 2

    runner = unittest.TextTestRunner(verbosity=verbosity)
    if len(args) > 0:
        filter = '|'.join(args)
        suite = filter_suite_by_re(suite, filter)
    result = runner.run(suite)
    # Clean up stale threads from poorly cleaned-up tests.
    # TODO: make that not a problem, jeez
    for thread in threading.enumerate():
        if thread is not threading.currentThread():
            thread.join(timeout=1)
    # Exit correctly
    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == '__main__':
    main()
