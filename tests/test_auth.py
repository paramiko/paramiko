# Copyright (C) 2008  Jeff Forcier <jeff@bitprophet.org>
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
Some unit tests for authenticating over a Transport.
"""

import sys
import threading
import unittest

from ssh import Transport, ServerInterface, RSAKey, DSSKey, \
    SSHException, BadAuthenticationType, InteractiveQuery, ChannelException, \
    AuthenticationException
from ssh import AUTH_FAILED, AUTH_PARTIALLY_SUCCESSFUL, AUTH_SUCCESSFUL
from ssh import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from loop import LoopSocket


class NullServer (ServerInterface):
    paranoid_did_password = False
    paranoid_did_public_key = False
    paranoid_key = DSSKey.from_private_key_file('tests/test_dss.key')
    
    def get_allowed_auths(self, username):
        if username == 'slowdive':
            return 'publickey,password'
        if username == 'paranoid':
            if not self.paranoid_did_password and not self.paranoid_did_public_key:
                return 'publickey,password'
            elif self.paranoid_did_password:
                return 'publickey'
            else:
                return 'password'
        if username == 'commie':
            return 'keyboard-interactive'
        if username == 'utf8':
            return 'password'
        if username == 'non-utf8':
            return 'password'
        return 'publickey'

    def check_auth_password(self, username, password):
        if (username == 'slowdive') and (password == 'pygmalion'):
            return AUTH_SUCCESSFUL
        if (username == 'paranoid') and (password == 'paranoid'):
            # 2-part auth (even openssh doesn't support this)
            self.paranoid_did_password = True
            if self.paranoid_did_public_key:
                return AUTH_SUCCESSFUL
            return AUTH_PARTIALLY_SUCCESSFUL
        if (username == 'utf8') and (password == u'\u2022'):
            return AUTH_SUCCESSFUL
        if (username == 'non-utf8') and (password == '\xff'):
            return AUTH_SUCCESSFUL
        if username == 'bad-server':
            raise Exception("Ack!")
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if (username == 'paranoid') and (key == self.paranoid_key):
            # 2-part auth
            self.paranoid_did_public_key = True
            if self.paranoid_did_password:
                return AUTH_SUCCESSFUL
            return AUTH_PARTIALLY_SUCCESSFUL
        return AUTH_FAILED
    
    def check_auth_interactive(self, username, submethods):
        if username == 'commie':
            self.username = username
            return InteractiveQuery('password', 'Please enter a password.', ('Password', False))
        return AUTH_FAILED
    
    def check_auth_interactive_response(self, responses):
        if self.username == 'commie':
            if (len(responses) == 1) and (responses[0] == 'cat'):
                return AUTH_SUCCESSFUL
        return AUTH_FAILED


class AuthTest (unittest.TestCase):

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
    
    def start_server(self):
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        self.public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        self.event = threading.Event()
        self.server = NullServer()
        self.assert_(not self.event.isSet())
        self.ts.start_server(self.event, self.server)
    
    def verify_finished(self):
        self.event.wait(1.0)
        self.assert_(self.event.isSet())
        self.assert_(self.ts.is_active())

    def test_1_bad_auth_type(self):
        """
        verify that we get the right exception when an unsupported auth
        type is requested.
        """
        self.start_server()
        try:
            self.tc.connect(hostkey=self.public_host_key,
                            username='unknown', password='error')
            self.assert_(False)
        except:
            etype, evalue, etb = sys.exc_info()
            self.assertEquals(BadAuthenticationType, etype)
            self.assertEquals(['publickey'], evalue.allowed_types)

    def test_2_bad_password(self):
        """
        verify that a bad password gets the right exception, and that a retry
        with the right password works.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)
        try:
            self.tc.auth_password(username='slowdive', password='error')
            self.assert_(False)
        except:
            etype, evalue, etb = sys.exc_info()
            self.assert_(issubclass(etype, AuthenticationException))
        self.tc.auth_password(username='slowdive', password='pygmalion')
        self.verify_finished()
    
    def test_3_multipart_auth(self):
        """
        verify that multipart auth works.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)
        remain = self.tc.auth_password(username='paranoid', password='paranoid')
        self.assertEquals(['publickey'], remain)
        key = DSSKey.from_private_key_file('tests/test_dss.key')
        remain = self.tc.auth_publickey(username='paranoid', key=key)
        self.assertEquals([], remain)
        self.verify_finished()

    def test_4_interactive_auth(self):
        """
        verify keyboard-interactive auth works.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)

        def handler(title, instructions, prompts):
            self.got_title = title
            self.got_instructions = instructions
            self.got_prompts = prompts
            return ['cat']
        remain = self.tc.auth_interactive('commie', handler)
        self.assertEquals(self.got_title, 'password')
        self.assertEquals(self.got_prompts, [('Password', False)])
        self.assertEquals([], remain)
        self.verify_finished()
        
    def test_5_interactive_auth_fallback(self):
        """
        verify that a password auth attempt will fallback to "interactive"
        if password auth isn't supported but interactive is.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)
        remain = self.tc.auth_password('commie', 'cat')
        self.assertEquals([], remain)
        self.verify_finished()

    def test_6_auth_utf8(self):
        """
        verify that utf-8 encoding happens in authentication.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)
        remain = self.tc.auth_password('utf8', u'\u2022')
        self.assertEquals([], remain)
        self.verify_finished()

    def test_7_auth_non_utf8(self):
        """
        verify that non-utf-8 encoded passwords can be used for broken
        servers.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)
        remain = self.tc.auth_password('non-utf8', '\xff')
        self.assertEquals([], remain)
        self.verify_finished()

    def test_8_auth_gets_disconnected(self):
        """
        verify that we catch a server disconnecting during auth, and report
        it as an auth failure.
        """
        self.start_server()
        self.tc.connect(hostkey=self.public_host_key)
        try:
            remain = self.tc.auth_password('bad-server', 'hello')
        except:
            etype, evalue, etb = sys.exc_info()
            self.assert_(issubclass(etype, AuthenticationException))
