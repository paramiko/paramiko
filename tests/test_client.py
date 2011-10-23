# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Some unit tests for SSHClient.
"""

import socket
import threading
import time
import unittest
import weakref
from binascii import hexlify

import ssh


class NullServer (ssh.ServerInterface):

    def get_allowed_auths(self, username):
        if username == 'slowdive':
            return 'publickey,password'
        return 'publickey'

    def check_auth_password(self, username, password):
        if (username == 'slowdive') and (password == 'pygmalion'):
            return ssh.AUTH_SUCCESSFUL
        return ssh.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if (key.get_name() == 'ssh-dss') and (hexlify(key.get_fingerprint()) == '4478f0b9a23cc5182009ff755bc1d26c'):
            return ssh.AUTH_SUCCESSFUL
        return ssh.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return ssh.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        if command != 'yes':
            return False
        return True


class SSHClientTest (unittest.TestCase):

    def setUp(self):
        self.sockl = socket.socket()
        self.sockl.bind(('localhost', 0))
        self.sockl.listen(1)
        self.addr, self.port = self.sockl.getsockname()
        self.event = threading.Event()
        thread = threading.Thread(target=self._run)
        thread.start()

    def tearDown(self):
        if hasattr(self, 'tc'):
            self.tc.close()
        self.ts.close()
        self.socks.close()
        self.sockl.close()

    def _run(self):
        self.socks, addr = self.sockl.accept()
        self.ts = ssh.Transport(self.socks)
        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        self.ts.add_server_key(host_key)
        server = NullServer()
        self.ts.start_server(self.event, server)


    def test_1_client(self):
        """
        verify that the SSHClient stuff works too.
        """
        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = ssh.RSAKey(data=str(host_key))

        self.tc = ssh.SSHClient()
        self.tc.get_host_keys().add('[%s]:%d' % (self.addr, self.port), 'ssh-rsa', public_host_key)
        self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

        self.event.wait(1.0)
        self.assert_(self.event.isSet())
        self.assert_(self.ts.is_active())
        self.assertEquals('slowdive', self.ts.get_username())
        self.assertEquals(True, self.ts.is_authenticated())

        stdin, stdout, stderr = self.tc.exec_command('yes')
        schan = self.ts.accept(1.0)

        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        self.assertEquals('Hello there.\n', stdout.readline())
        self.assertEquals('', stdout.readline())
        self.assertEquals('This is on stderr.\n', stderr.readline())
        self.assertEquals('', stderr.readline())

        stdin.close()
        stdout.close()
        stderr.close()

    def test_2_client_dsa(self):
        """
        verify that SSHClient works with a DSA key.
        """
        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = ssh.RSAKey(data=str(host_key))

        self.tc = ssh.SSHClient()
        self.tc.get_host_keys().add('[%s]:%d' % (self.addr, self.port), 'ssh-rsa', public_host_key)
        self.tc.connect(self.addr, self.port, username='slowdive', key_filename='tests/test_dss.key')

        self.event.wait(1.0)
        self.assert_(self.event.isSet())
        self.assert_(self.ts.is_active())
        self.assertEquals('slowdive', self.ts.get_username())
        self.assertEquals(True, self.ts.is_authenticated())

        stdin, stdout, stderr = self.tc.exec_command('yes')
        schan = self.ts.accept(1.0)

        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        self.assertEquals('Hello there.\n', stdout.readline())
        self.assertEquals('', stdout.readline())
        self.assertEquals('This is on stderr.\n', stderr.readline())
        self.assertEquals('', stderr.readline())

        stdin.close()
        stdout.close()
        stderr.close()

    def test_3_multiple_key_files(self):
        """
        verify that SSHClient accepts and tries multiple key files.
        """
        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = ssh.RSAKey(data=str(host_key))

        self.tc = ssh.SSHClient()
        self.tc.get_host_keys().add('[%s]:%d' % (self.addr, self.port), 'ssh-rsa', public_host_key)
        self.tc.connect(self.addr, self.port, username='slowdive', key_filename=[ 'tests/test_rsa.key', 'tests/test_dss.key' ])

        self.event.wait(1.0)
        self.assert_(self.event.isSet())
        self.assert_(self.ts.is_active())
        self.assertEquals('slowdive', self.ts.get_username())
        self.assertEquals(True, self.ts.is_authenticated())

    def test_4_auto_add_policy(self):
        """
        verify that SSHClient's AutoAddPolicy works.
        """
        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = ssh.RSAKey(data=str(host_key))

        self.tc = ssh.SSHClient()
        self.tc.set_missing_host_key_policy(ssh.AutoAddPolicy())
        self.assertEquals(0, len(self.tc.get_host_keys()))
        self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

        self.event.wait(1.0)
        self.assert_(self.event.isSet())
        self.assert_(self.ts.is_active())
        self.assertEquals('slowdive', self.ts.get_username())
        self.assertEquals(True, self.ts.is_authenticated())
        self.assertEquals(1, len(self.tc.get_host_keys()))
        self.assertEquals(public_host_key, self.tc.get_host_keys()['[%s]:%d' % (self.addr, self.port)]['ssh-rsa'])

    def test_5_cleanup(self):
        """
        verify that when an SSHClient is collected, its transport (and the
        transport's packetizer) is closed.
        """
        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = ssh.RSAKey(data=str(host_key))

        self.tc = ssh.SSHClient()
        self.tc.set_missing_host_key_policy(ssh.AutoAddPolicy())
        self.assertEquals(0, len(self.tc.get_host_keys()))
        self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

        self.event.wait(1.0)
        self.assert_(self.event.isSet())
        self.assert_(self.ts.is_active())

        p = weakref.ref(self.tc._transport.packetizer)
        self.assert_(p() is not None)
        del self.tc
        # hrm, sometimes p isn't cleared right away.  why is that?
        st = time.time()
        while (time.time() - st < 5.0) and (p() is not None):
            time.sleep(0.1)
        self.assert_(p() is None)

