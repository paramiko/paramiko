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

import gc
import platform
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
from paramiko.common import PY2
from paramiko.ssh_exception import SSHException, AuthenticationException


FINGERPRINTS = {
    'ssh-dss': b'\x44\x78\xf0\xb9\xa2\x3c\xc5\x18\x20\x09\xff\x75\x5b\xc1\xd2\x6c',
    'ssh-rsa': b'\x60\x73\x38\x44\xcb\x51\x86\x65\x7f\xde\xda\xa2\x2b\x5a\x57\xd5',
    'ecdsa-sha2-nistp256': b'\x25\x19\xeb\x55\xe6\xa1\x47\xff\x4f\x38\xd2\x75\x6f\xa5\xd5\x60',
    'ssh-ed25519': b'\xb3\xd5"\xaa\xf9u^\xe8\xcd\x0e\xea\x02\xb9)\xa2\x80',
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
        if (username == 'slowdive') and (password == 'unresponsive-server'):
            time.sleep(5)
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
        if command != b'yes':
            return False
        return True

    def check_channel_env_request(self, channel, name, value):
        if name == 'INVALID_ENV':
            return False

        if not hasattr(channel, 'env'):
            setattr(channel, 'env', {})

        channel.env[name] = value
        return True


class SSHClientTest (unittest.TestCase):

    def setUp(self):
        self.sockl = socket.socket()
        self.sockl.bind(('localhost', 0))
        self.sockl.listen(1)
        self.addr, self.port = self.sockl.getsockname()
        self.connect_kwargs = dict(
            hostname=self.addr,
            port=self.port,
            username='slowdive',
            look_for_keys=False,
        )
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
        keypath = test_path('test_rsa.key')
        host_key = paramiko.RSAKey.from_private_key_file(keypath)
        self.ts.add_server_key(host_key)
        keypath = test_path('test_ecdsa_256.key')
        host_key = paramiko.ECDSAKey.from_private_key_file(keypath)
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
        self.tc.connect(**dict(self.connect_kwargs, **kwargs))

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
        self._test_connection(key_filename=test_path('test_ecdsa_256.key'))

    def test_client_ed25519(self):
        self._test_connection(key_filename=test_path('test_ed25519.key'))

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
            (['dss', 'rsa', 'ecdsa_256'], ['dss']), # Try ECDSA but fail
            (['rsa', 'ecdsa_256'], ['ecdsa']), # ECDSA success
        ):
            try:
                self._test_connection(
                    key_filename=[
                        test_path('test_{0}.key'.format(x)) for x in attempt
                    ],
                    allowed_keys=[types_[x] for x in accept],
                )
            finally:
                # Clean up to avoid occasional gc-related deadlocks.
                # TODO: use nose test generators after nose port
                self.tearDown()
                self.setUp()

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
        hostname = '[%s]:%d' % (self.addr, self.port)
        key_file = test_path('test_ecdsa_256.key')
        public_host_key = paramiko.ECDSAKey.from_private_key_file(key_file)

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(password='pygmalion', **self.connect_kwargs)

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual('slowdive', self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())
        self.assertEqual(1, len(self.tc.get_host_keys()))
        new_host_key = list(self.tc.get_host_keys()[hostname].values())[0]
        self.assertEqual(public_host_key, new_host_key)

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
        # Skipped on PyPy because it fails on travis for unknown reasons
        if platform.python_implementation() == "PyPy":
            return

        threading.Thread(target=self._run).start()

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(**dict(self.connect_kwargs, password='pygmalion'))

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())

        p = weakref.ref(self.tc._transport.packetizer)
        self.assertTrue(p() is not None)
        self.tc.close()
        del self.tc

        # force a collection to see whether the SSHClient object is deallocated
        # 2 GCs are needed on PyPy, time is needed for Python 3
        time.sleep(0.3)
        gc.collect()
        gc.collect()

        self.assertTrue(p() is None)

    def test_client_can_be_used_as_context_manager(self):
        """
        verify that an SSHClient can be used a context manager
        """
        threading.Thread(target=self._run).start()

        with paramiko.SSHClient() as tc:
            self.tc = tc
            self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.assertEquals(0, len(self.tc.get_host_keys()))
            self.tc.connect(**dict(self.connect_kwargs, password='pygmalion'))

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
        kwargs = dict(self.connect_kwargs, banner_timeout=0.5)
        self.assertRaises(
            paramiko.SSHException,
            self.tc.connect,
            **kwargs
        )

    def test_8_auth_trickledown(self):
        """
        Failed key auth doesn't prevent subsequent pw auth from succeeding
        """
        # NOTE: re #387, re #394
        # If pkey module used within Client._auth isn't correctly handling auth
        # errors (e.g. if it allows things like ValueError to bubble up as per
        # midway through #394) client.connect() will fail (at key load step)
        # instead of succeeding (at password step)
        kwargs = dict(
            # Password-protected key whose passphrase is not 'pygmalion' (it's
            # 'television' as per tests/test_pkey.py). NOTE: must use
            # key_filename, loading the actual key here with PKey will except
            # immediately; we're testing the try/except crap within Client.
            key_filename=[test_path('test_rsa_password.key')],
            # Actual password for default 'slowdive' user
            password='pygmalion',
        )
        self._test_connection(**kwargs)

    def test_9_auth_timeout(self):
        """
        verify that the SSHClient has a configurable auth timeout
        """
        # Connect with a half second auth timeout
        self.assertRaises(
            AuthenticationException,
            self._test_connection,
            password='unresponsive-server',
            auth_timeout=0.5,
        )

    def _client_host_key_bad(self, host_key):
        threading.Thread(target=self._run).start()
        hostname = '[%s]:%d' % (self.addr, self.port)

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.WarningPolicy())
        known_hosts = self.tc.get_host_keys()
        known_hosts.add(hostname, host_key.get_name(), host_key)

        self.assertRaises(
            paramiko.BadHostKeyException,
            self.tc.connect,
            password='pygmalion',
            **self.connect_kwargs
        )

    def _client_host_key_good(self, ktype, kfile):
        threading.Thread(target=self._run).start()
        hostname = '[%s]:%d' % (self.addr, self.port)

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.RejectPolicy())
        host_key = ktype.from_private_key_file(test_path(kfile))
        known_hosts = self.tc.get_host_keys()
        known_hosts.add(hostname, host_key.get_name(), host_key)

        self.tc.connect(password='pygmalion', **self.connect_kwargs)
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual(True, self.ts.is_authenticated())

    def test_host_key_negotiation_1(self):
        host_key = paramiko.ECDSAKey.generate()
        self._client_host_key_bad(host_key)

    def test_host_key_negotiation_2(self):
        host_key = paramiko.RSAKey.generate(2048)
        self._client_host_key_bad(host_key)

    def test_host_key_negotiation_3(self):
        self._client_host_key_good(paramiko.ECDSAKey, 'test_ecdsa_256.key')

    def test_host_key_negotiation_4(self):
        self._client_host_key_good(paramiko.RSAKey, 'test_rsa.key')

    def test_update_environment(self):
        """
        Verify that environment variables can be set by the client.
        """
        threading.Thread(target=self._run).start()

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(self.addr, self.port, username='slowdive', password='pygmalion')

        self.event.wait(1.0)
        self.assertTrue(self.event.isSet())
        self.assertTrue(self.ts.is_active())

        target_env = {b'A': b'B', b'C': b'd'}

        self.tc.exec_command('yes', environment=target_env)
        schan = self.ts.accept(1.0)
        self.assertEqual(target_env, getattr(schan, 'env', {}))
        schan.close()

        # Cannot use assertRaises in context manager mode as it is not supported
        # in Python 2.6.
        try:
            # Verify that a rejection by the server can be detected
            self.tc.exec_command('yes', environment={b'INVALID_ENV': b''})
        except SSHException as e:
            self.assertTrue('INVALID_ENV' in str(e),
                            'Expected variable name in error message')
            self.assertTrue(isinstance(e.args[1], SSHException),
                            'Expected original SSHException in exception')
        else:
            self.assertFalse(False, 'SSHException was not thrown.')


    def test_missing_key_policy_accepts_classes_or_instances(self):
        """
        Client.missing_host_key_policy() can take classes or instances.
        """
        # AN ACTUAL UNIT TEST?! GOOD LORD
        # (But then we have to test a private API...meh.)
        client = paramiko.SSHClient()
        # Default
        assert isinstance(client._policy, paramiko.RejectPolicy)
        # Hand in an instance (classic behavior)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        assert isinstance(client._policy, paramiko.AutoAddPolicy)
        # Hand in just the class (new behavior)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        assert isinstance(client._policy, paramiko.AutoAddPolicy)
