# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
# Copyright (C) 2013-2014 science + computing ag
# Author: Sebastian Deiss <sebastian.deiss@t-online.de>
#
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
Unit Tests for the GSS-API / SSPI SSHv2 Diffie-Hellman Key Exchange and user
authentication
"""


import socket
import threading
import unittest

import paramiko

from .util import KerberosTestCase, update_env


class NullServer (paramiko.ServerInterface):

    def get_allowed_auths(self, username):
        return 'gssapi-keyex'

    def check_auth_gssapi_keyex(self, username,
                                gss_authenticated=paramiko.AUTH_FAILED,
                                cc_file=None):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        UseGSSAPI = True
        return UseGSSAPI

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        if command != b"yes":
            return False
        return True


class GSSKexTest(KerberosTestCase):
    def setUp(self):
        self.username = self.realm.user_princ
        self.hostname = socket.getfqdn(self.realm.hostname)
        self.sockl = socket.socket()
        self.sockl.bind((self.realm.hostname, 0))
        self.sockl.listen(1)
        self.addr, self.port = self.sockl.getsockname()
        self.event = threading.Event()
        update_env(self, self.realm.env)
        thread = threading.Thread(target=self._run)
        thread.start()

    def tearDown(self):
        for attr in "tc ts socks sockl".split():
            if hasattr(self, attr):
                getattr(self, attr).close()

    def _run(self):
        self.socks, addr = self.sockl.accept()
        self.ts = paramiko.Transport(self.socks, gss_kex=True)
        host_key = paramiko.RSAKey.from_private_key_file('tests/test_rsa.key')
        self.ts.add_server_key(host_key)
        self.ts.set_gss_host(self.realm.hostname)
        try:
            self.ts.load_server_moduli()
        except:
            print('(Failed to load moduli -- gex will be unsupported.)')
        server = NullServer()
        self.ts.start_server(self.event, server)

    def _test_gsskex_and_auth(self, gss_host, rekey=False):
        """
        Verify that Paramiko can handle SSHv2 GSS-API / SSPI authenticated
        Diffie-Hellman Key Exchange and user authentication with the GSS-API
        context created during key exchange.
        """
        host_key = paramiko.RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        self.tc = paramiko.SSHClient()
        self.tc.get_host_keys().add('[%s]:%d' % (self.hostname, self.port),
                                    'ssh-rsa', public_host_key)
        self.tc.connect(self.hostname, self.port, username=self.username,
                        gss_auth=True, gss_kex=True, gss_host=gss_host)

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual(self.username, self.ts.get_username())
        self.assertTrue(self.ts.is_authenticated())
        self.assertTrue(self.tc.get_transport().gss_kex_used)

        stdin, stdout, stderr = self.tc.exec_command('yes')
        schan = self.ts.accept(1.0)
        if rekey:
            self.tc.get_transport().renegotiate_keys()

        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        self.assertEqual('Hello there.\n', stdout.readline())
        self.assertEqual('', stdout.readline())
        self.assertEqual('This is on stderr.\n', stderr.readline())
        self.assertEqual('', stderr.readline())

        stdin.close()
        stdout.close()
        stderr.close()

    def test_gsskex_and_auth(self):
        """
        Verify that Paramiko can handle SSHv2 GSS-API / SSPI authenticated
        Diffie-Hellman Key Exchange and user authentication with the GSS-API
        context created during key exchange.
        """
        self._test_gsskex_and_auth(gss_host=None)

    @unittest.expectedFailure  # https://github.com/paramiko/paramiko/issues/1312
    def test_gsskex_and_auth_rekey(self):
        """
        Verify that Paramiko can rekey.
        """
        self._test_gsskex_and_auth(gss_host=None, rekey=True)
