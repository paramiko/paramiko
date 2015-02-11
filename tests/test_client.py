# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
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
Some unit tests for SSHClient.
"""

from __future__ import with_statement

import socket
from tempfile import mkstemp
import threading
import unittest
import weakref
import warnings
import os
import time
from tests.util import test_path
import paramiko
from paramiko.common import PY2, b
from paramiko.ssh_exception import SSHException


FINGERPRINTS = {
    'ssh-dss': b'\x44\x78\xf0\xb9\xa2\x3c\xc5\x18\x20\x09\xff\x75\x5b\xc1\xd2\x6c',
    'ssh-rsa': b'\x60\x73\x38\x44\xcb\x51\x86\x65\x7f\xde\xda\xa2\x2b\x5a\x57\xd5',
    'ecdsa-sha2-nistp256': b'\x25\x19\xeb\x55\xe6\xa1\x47\xff\x4f\x38\xd2\x75\x6f\xa5\xd5\x60',
}


class NullServer (paramiko.ServerInterface):
    def __init__(self, *args, **kwargs):
        # Allow tests to enable/disable specific key types
        self.__allowed_keys = kwargs.pop('allowed_keys', [])
        super(NullServer, self).__init__(*args, **kwargs)

    def get_allowed_auths(self, username):
        if username == 'slowdive':
            return 'publickey,password'
        return 'publickey'

    def check_auth_password(self, username, password):
        if (username == 'slowdive') and (password == 'pygmalion'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        try:
            expected = FINGERPRINTS[key.get_name()]
        except KeyError:
            return paramiko.AUTH_FAILED
        if (
            key.get_name() in self.__allowed_keys and
            key.get_fingerprint() == expected
        ):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

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

    def tearDown(self):
        for attr in "tc ts socks sockl".split():
            if hasattr(self, attr):
                getattr(self, attr).close()

    def _run(self, allowed_keys=None, delay=0):
        if allowed_keys is None:
            allowed_keys = FINGERPRINTS.keys()
        self.socks, addr = self.sockl.accept()
        self.ts = paramiko.Transport(self.socks)
        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        self.ts.add_server_key(host_key)
        server = NullServer(allowed_keys=allowed_keys)
        if delay:
            time.sleep(delay)
        self.ts.start_server(self.event, server)

    def _test_connection(self, **kwargs):
        """
        (Most) kwargs get passed directly into SSHClient.connect().

        The exception is ``allowed_keys`` which is stripped and handed to the
        ``NullServer`` used for testing.
        """
        run_kwargs = {'allowed_keys': kwargs.pop('allowed_keys', None)}
        # Server setup
        threading.Thread(target=self._run, kwargs=run_kwargs).start()
        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        # Client setup
        self.tc = paramiko.SSHClient()
        self.tc.get_host_keys().add('[%s]:%d' % (self.addr, self.port), 'ssh-rsa', public_host_key)

        # Actual connection
        self.tc.connect(self.addr, self.port, username='slowdive', **kwargs)

        # Authentication successful?
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual('slowdive', self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())

        # Command execution functions?
        stdin, stdout, stderr = self.tc.exec_command('yes')
        schan = self.ts.accept(1.0)

        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        self.assertEqual('Hello there.\n', stdout.readline())
        self.assertEqual('', stdout.readline())
        self.assertEqual('This is on stderr.\n', stderr.readline())
        self.assertEqual('', stderr.readline())

        # Cleanup
        stdin.close()
        stdout.close()
        stderr.close()

    def test_1_client(self):
        """
        verify that the SSHClient stuff works too.
        """
        self._test_connection(password='pygmalion')

    def test_2_client_dsa(self):
        """
        verify that SSHClient works with a DSA key.
        """
        self._test_connection(key_filename=test_path('test_dss.key'))

    def test_client_rsa(self):
        """
        verify that SSHClient works with an RSA key.
        """
        self._test_connection(key_filename=test_path('test_rsa.key'))

    def test_2_5_client_ecdsa(self):
        """
        verify that SSHClient works with an ECDSA key.
        """
        self._test_connection(key_filename=test_path('test_ecdsa.key'))

    def test_3_multiple_key_files(self):
        """
        verify that SSHClient accepts and tries multiple key files.
        """
        # This is dumb :(
        types_ = {
            'rsa': 'ssh-rsa',
            'dss': 'ssh-dss',
            'ecdsa': 'ecdsa-sha2-nistp256',
        }
        # Various combos of attempted & valid keys
        # TODO: try every possible combo using itertools functions
        for attempt, accept in (
            (['rsa', 'dss'], ['dss']), # Original test #3
            (['dss', 'rsa'], ['dss']), # Ordering matters sometimes, sadly
            (['dss', 'rsa', 'ecdsa'], ['dss']), # Try ECDSA but fail
            (['rsa', 'ecdsa'], ['ecdsa']), # ECDSA success
        ):
            self._test_connection(
                key_filename=[
                    test_path('test_{0}.key'.format(x)) for x in attempt
                ],
                allowed_keys=[types_[x] for x in accept],
            )

    def test_multiple_key_files_failure(self):
        """
        Expect failure when multiple keys in play and none are accepted
        """
        # Until #387 is fixed we have to catch a high-up exception since
        # various platforms trigger different errors here >_<
        self.assertRaises(SSHException,
            self._test_connection,
            key_filename=[test_path('test_rsa.key')],
            allowed_keys=['ecdsa-sha2-nistp256'],
        )

    def test_4_auto_add_policy(self):
        """
        verify that SSHClient's AutoAddPolicy works.
        """
        threading.Thread(target=self._run).start()
        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual('slowdive', self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())
        self.assertEqual(1, len(self.tc.get_host_keys()))
        self.assertEqual(public_host_key, self.tc.get_host_keys()['[%s]:%d' % (self.addr, self.port)]['ssh-rsa'])

    def test_5_save_host_keys(self):
        """
        verify that SSHClient correctly saves a known_hosts file.
        """
        warnings.filterwarnings('ignore', 'tempnam.*')

        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())
        fd, localname = mkstemp()
        os.close(fd)

        client = paramiko.SSHClient()
        self.assertEquals(0, len(client.get_host_keys()))

        host_id = '[%s]:%d' % (self.addr, self.port)

        client.get_host_keys().add(host_id, 'ssh-rsa', public_host_key)
        self.assertEquals(1, len(client.get_host_keys()))
        self.assertEquals(public_host_key, client.get_host_keys()[host_id]['ssh-rsa'])

        client.save_host_keys(localname)

        with open(localname) as fd:
            assert host_id in fd.read()

        os.unlink(localname)

    def test_6_cleanup(self):
        """
        verify that when an SSHClient is collected, its transport (and the
        transport's packetizer) is closed.
        """
        # Unclear why this is borked on Py3, but it is, and does not seem worth
        # pursuing at the moment.
        # XXX: It's the release of the references to e.g packetizer that fails
        # in py3...
        if not PY2:
            return
        threading.Thread(target=self._run).start()
        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())

        p = weakref.ref(self.tc._transport.packetizer)
        self.assertTrue(p() is not None)
        self.tc.close()
        del self.tc

        # hrm, sometimes p isn't cleared right away.  why is that?
        #st = time.time()
        #while (time.time() - st < 5.0) and (p() is not None):
        #    time.sleep(0.1)

        # instead of dumbly waiting for the GC to collect, force a collection
        # to see whether the SSHClient object is deallocated correctly
        import gc
        gc.collect()

        self.assertTrue(p() is None)

    def test_client_can_be_used_as_context_manager(self):
        """
        verify that an SSHClient can be used a context manager
        """
        threading.Thread(target=self._run).start()
        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        with paramiko.SSHClient() as tc:
            self.tc = tc
            self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.assertEquals(0, len(self.tc.get_host_keys()))
            self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

            self.event.wait(1.0)
            self.assertTrue(self.event.is_set())
            self.assertTrue(self.ts.is_active())

            self.assertTrue(self.tc._transport is not None)

        self.assertTrue(self.tc._transport is None)

    def test_7_banner_timeout(self):
        """
        verify that the SSHClient has a configurable banner timeout.
        """
        # Start the thread with a 1 second wait.
        threading.Thread(target=self._run, kwargs={'delay': 1}).start()
        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        self.tc = paramiko.SSHClient()
        self.tc.get_host_keys().add('[%s]:%d' % (self.addr, self.port), 'ssh-rsa', public_host_key)
        # Connect with a half second banner timeout.
        self.assertRaises(
            paramiko.SSHException,
            self.tc.connect,
            self.addr,
            self.port,
            username='slowdive',
            password='pygmalion',
            banner_timeout=0.5
        )
