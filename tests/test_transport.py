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
Some unit tests for the ssh2 protocol in Transport.
"""

import sys, unittest, threading
from paramiko import Transport, SecurityOptions, ServerInterface, RSAKey, DSSKey, \
    SSHException, BadAuthenticationType
from paramiko import AUTH_FAILED, AUTH_SUCCESSFUL
from loop import LoopSocket


class NullServer (ServerInterface):
    def get_allowed_auths(self, username):
        if username == 'slowdive':
            return 'publickey,password'
        return 'publickey'

    def check_auth_password(self, username, password):
        if (username == 'slowdive') and (password == 'pygmalion'):
            return AUTH_SUCCESSFUL
        return AUTH_FAILED


class TransportTest (unittest.TestCase):

    def setUp(self):
        self.socks = LoopSocket()
        self.sockc = LoopSocket()
        self.sockc.link(self.socks)
        self.tc = Transport(self.sockc)
        self.ts = Transport(self.socks)

    def tearDown(self):
        self.tc.close()
        self.ts.close()
        self.socks.close()
        self.sockc.close()

    def test_1_security_options(self):
        o = self.tc.get_security_options()
        self.assertEquals(type(o), SecurityOptions)
        self.assert_(('aes256-cbc', 'blowfish-cbc') != o.ciphers)
        o.ciphers = ('aes256-cbc', 'blowfish-cbc')
        self.assertEquals(('aes256-cbc', 'blowfish-cbc'), o.ciphers)
        try:
            o.ciphers = ('aes256-cbc', 'made-up-cipher')
            self.assert_(False)
        except ValueError:
            pass
        try:
            o.ciphers = 23
            self.assert_(False)
        except TypeError:
            pass

    def test_2_simple(self):
        """
        verify that we can establish an ssh link with ourselves across the
        loopback sockets.  this is hardly "simple" but it's simpler than the
        later tests. :)
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assert_(not event.isSet())
        self.ts.start_server(event, server)
        self.tc.ultra_debug = True
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

    def test_3_bad_auth_type(self):
        """
        verify that we get the right exception when an unsupported auth
        type is requested.
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assert_(not event.isSet())
        self.ts.start_server(event, server)
        self.tc.ultra_debug = True
        try:
            self.tc.connect(hostkey=public_host_key,
                            username='unknown', password='error')
            self.assert_(False)
        except:
            etype, evalue, etb = sys.exc_info()
            self.assertEquals(BadAuthenticationType, etype)
            self.assertEquals(['publickey'], evalue.allowed_types)

    def test_4_bad_password(self):
        """
        verify that a bad password gets the right exception, and that a retry
        with the right password works.
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assert_(not event.isSet())
        self.ts.start_server(event, server)
        self.tc.ultra_debug = True
        self.tc.connect(hostkey=public_host_key)
        try:
            self.tc.auth_password(username='slowdive', password='error')
            self.assert_(False)
        except:
            etype, evalue, etb = sys.exc_info()
            self.assertEquals(SSHException, etype)
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
     
     
