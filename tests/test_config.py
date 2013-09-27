# Copyright (C) 2013 Tomaz Muraus <tomaz@tomaz.me>
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
from __future__ import with_statement

import os
import sys
import unittest
from os.path import join as pjoin

from mock import patch

from paramiko.config import SSHConfig

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
FIXTURES_DIR = pjoin(CURRENT_DIR, 'fixtures/')


class SSHConfigTestCase(unittest.TestCase):
    def test_config_parsing(self):
        try:
            file_obj = open(pjoin(FIXTURES_DIR, 'config1'))
            config = SSHConfig()
            config.parse(file_obj)
        finally:
            file_obj.close()

        host = config.lookup('*')
        self.assertEqual(host['hostname'], '*')
        self.assertEqual(host['controlmaster'], 'auto')
        self.assertEqual(host['forwardagent'], 'yes')

        remote_user = os.getenv('USER')
        hostname = '*'
        port = 22

        # Verify that variables are replaced
        self.assertEqual(host['controlpath'], '~/.ssh/master-%s@%s:%s' %
                         (remote_user, hostname, port))

        # Verify that other host inherit attributes from *
        host = config.lookup('example1.com')
        self.assertEqual(host['hostname'], 'example1.com')
        self.assertEqual(host['user'], 'foo1')
        self.assertEqual(host['identityfile'],
                         [os.path.expanduser('~/.ssh/id_rsa_example1')])

        # Verify that variables are replaced
        remote_user = 'foo1'
        hostname = 'example1.com'
        port = 22
        self.assertEqual(host['controlpath'], '~/.ssh/master-%s@%s:%s' %
                         (remote_user, hostname, port))

        # Inherited properties
        self.assertEqual(host['controlmaster'], 'auto')
        self.assertEqual(host['forwardagent'], 'yes')

        host = config.lookup('example2.com')
        self.assertEqual(host['hostname'], 'example2.com')
        self.assertEqual(host['user'], 'foo2')
        self.assertEqual(host['port'], '5656')
        self.assertEqual(host['identityfile'],
                         [os.path.expanduser('~/.ssh/id_rsa_example2')])

        # Verify that variables are replaced
        remote_user = 'foo2'
        hostname = 'example2.com'
        port = 5656
        self.assertEqual(host['controlpath'], '~/.ssh/master-%s@%s:%s' %
                         (remote_user, hostname, port))

        # Inherited properties
        self.assertEqual(host['controlmaster'], 'auto')
        self.assertEqual(host['forwardagent'], 'yes')

    @patch('socket.gethostname')
    @patch('socket.getaddrinfo')
    def test_config_parsing_with_address_family(self, mock_getaddrinfo,
                                                mock_gethostname):
        # In config2 AddressFamily option is specified which means LazyFqdn
        # should step into the address_family != 'any' branch

        mock_gethostname.return_value = 'localhost'
        mock_getaddrinfo.return_value = [(2, 2, 17, 'localhost.foo',
                                         ('127.0.0.1', 0))]

        try:
            file_obj = open(pjoin(FIXTURES_DIR, 'config2'))
            config = SSHConfig()
            config.parse(file_obj)
        finally:
            file_obj.close()

        host = config.lookup('*')
        self.assertEqual(host['hostname'], '*')
        self.assertEqual(host['controlmaster'], 'auto')
        self.assertEqual(host['forwardagent'], 'yes')

        remote_user = os.getenv('USER')
        hostname = '*'
        # Since AddressFamily is specified, localhost should be replaced with
        # a resolved canonical name
        canonname = 'localhost.foo'
        port = 22
        self.assertEqual(host['controlpath'], '~/.ssh/master-%s-%s@%s:%s' %
                         (remote_user, canonname, hostname, port))


if __name__ == '__main__':
    sys.exit(unittest.main())
