# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
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

import sys, time, threading, unittest
import select
from paramiko import Transport, SecurityOptions, ServerInterface, RSAKey, DSSKey, \
    SSHException, BadAuthenticationType, InteractiveQuery, util, ChannelException
from paramiko import AUTH_FAILED, AUTH_PARTIALLY_SUCCESSFUL, AUTH_SUCCESSFUL
from paramiko import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
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

    def check_channel_request(self, kind, chanid):
        if kind == 'bogus':
            return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        return OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        if command != 'yes':
            return False
        return True

    def check_channel_shell_request(self, channel):
        return True
    
    def check_global_request(self, kind, msg):
        self._global_request = kind
        return False


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
            
    def test_2_compute_key(self):
        self.tc.K = 123281095979686581523377256114209720774539068973101330872763622971399429481072519713536292772709507296759612401802191955568143056534122385270077606457721553469730659233569339356140085284052436697480759510519672848743794433460113118986816826624865291116513647975790797391795651716378444844877749505443714557929L
        self.tc.H = util.unhexify('0C8307CDE6856FF30BA93684EB0F04C2520E9ED3')
        self.tc.session_id = self.tc.H
        key = self.tc._compute_key('C', 32)
        self.assertEquals('207E66594CA87C44ECCBA3B3CD39FDDB378E6FDB0F97C54B2AA0CFBF900CD995',
            util.hexify(key))

    def test_3_simple(self):
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
        self.assertEquals(None, self.tc.get_username())
        self.assertEquals(None, self.ts.get_username())
        self.assertEquals(False, self.tc.is_authenticated())
        self.assertEquals(False, self.ts.is_authenticated())
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
        self.assertEquals('slowdive', self.tc.get_username())
        self.assertEquals('slowdive', self.ts.get_username())
        self.assertEquals(True, self.tc.is_authenticated())
        self.assertEquals(True, self.ts.is_authenticated())

    def test_4_special(self):
        """
        verify that the client can demand odd handshake settings, and can
        renegotiate keys in mid-stream.
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assert_(not event.isSet())
        self.ts.start_server(event, server)
        options = self.tc.get_security_options()
        options.ciphers = ('aes256-cbc',)
        options.digests = ('hmac-md5-96',)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
        self.assertEquals('aes256-cbc', self.tc.local_cipher)
        self.assertEquals('aes256-cbc', self.tc.remote_cipher)
        self.assertEquals(12, self.tc.packetizer.get_mac_size_out())
        self.assertEquals(12, self.tc.packetizer.get_mac_size_in())
        
        self.tc.send_ignore(1024)
        self.tc.renegotiate_keys()
        self.ts.send_ignore(1024)

    def test_5_keepalive(self):
        """
        verify that the keepalive will be sent.
        """
        self.tc.set_hexdump(True)
        
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assert_(not event.isSet())
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
        
        self.assertEquals(None, getattr(server, '_global_request', None))
        self.tc.set_keepalive(1)
        time.sleep(2)
        self.assertEquals('keepalive@lag.net', server._global_request)
        
    def test_6_bad_auth_type(self):
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
        try:
            self.tc.connect(hostkey=public_host_key,
                            username='unknown', password='error')
            self.assert_(False)
        except:
            etype, evalue, etb = sys.exc_info()
            self.assertEquals(BadAuthenticationType, etype)
            self.assertEquals(['publickey'], evalue.allowed_types)

    def test_7_bad_password(self):
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
            self.assert_(issubclass(etype, SSHException))
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
    
    def test_8_multipart_auth(self):
        """
        verify that multipart auth works.
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
        remain = self.tc.auth_password(username='paranoid', password='paranoid')
        self.assertEquals(['publickey'], remain)
        key = DSSKey.from_private_key_file('tests/test_dss.key')
        remain = self.tc.auth_publickey(username='paranoid', key=key)
        self.assertEquals([], remain)
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

    def test_9_interactive_auth(self):
        """
        verify keyboard-interactive auth works.
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

        def handler(title, instructions, prompts):
            self.got_title = title
            self.got_instructions = instructions
            self.got_prompts = prompts
            return ['cat']
        remain = self.tc.auth_interactive('commie', handler)
        self.assertEquals(self.got_title, 'password')
        self.assertEquals(self.got_prompts, [('Password', False)])
        self.assertEquals([], remain)
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
        
    def test_A_interactive_auth_fallback(self):
        """
        verify that a password auth attempt will fallback to "interactive"
        if password auth isn't supported but interactive is.
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
        remain = self.tc.auth_password('commie', 'cat')
        self.assertEquals([], remain)
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
            
    def test_B_exec_command(self):
        """
        verify that exec_command() does something reasonable.
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
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        try:
            chan.exec_command('no')
            self.assert_(False)
        except SSHException, x:
            pass
        
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        f = chan.makefile()
        self.assertEquals('Hello there.\n', f.readline())
        self.assertEquals('', f.readline())
        f = chan.makefile_stderr()
        self.assertEquals('This is on stderr.\n', f.readline())
        self.assertEquals('', f.readline())
        
        # now try it with combined stdout/stderr
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        chan.set_combine_stderr(True)        
        f = chan.makefile()
        self.assertEquals('Hello there.\n', f.readline())
        self.assertEquals('This is on stderr.\n', f.readline())
        self.assertEquals('', f.readline())

    def test_C_invoke_shell(self):
        """
        verify that invoke_shell() does something reasonable.
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
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)
        chan.send('communist j. cat\n')
        f = schan.makefile()
        self.assertEquals('communist j. cat\n', f.readline())
        chan.close()
        self.assertEquals('', f.readline())

    def test_D_channel_exception(self):
        """
        verify that ChannelException is thrown for a bad open-channel request.
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
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        try:
            chan = self.tc.open_channel('bogus')
            self.fail('expected exception')
        except ChannelException, x:
            self.assert_(x.code == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def test_E_exit_status(self):
        """
        verify that get_exit_status() works.
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
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        chan.exec_command('yes')
        schan.send('Hello there.\n')
        # trigger an EOF
        schan.shutdown_read()
        schan.shutdown_write()
        schan.send_exit_status(23)
        schan.close()
        
        f = chan.makefile()
        self.assertEquals('Hello there.\n', f.readline())
        self.assertEquals('', f.readline())
        self.assertEquals(23, chan.recv_exit_status())
        chan.close()

    def test_F_select(self):
        """
        verify that select() on a channel works.
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
        self.tc.auth_password(username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)

        # nothing should be ready        
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEquals([], r)
        self.assertEquals([], w)
        self.assertEquals([], e)
        
        schan.send('hello\n')
        
        # something should be ready now (give it 1 second to appear)
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEquals([chan], r)
        self.assertEquals([], w)
        self.assertEquals([], e)

        self.assertEquals('hello\n', chan.recv(6))
        
        # and, should be dead again now
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEquals([], r)
        self.assertEquals([], w)
        self.assertEquals([], e)

        schan.close()
        
        # detect eof?
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEquals([chan], r)
        self.assertEquals([], w)
        self.assertEquals([], e)
        self.assertEquals('', chan.recv(16))
        
        chan.close()
   
    def test_G_renegotiate(self):
        """
        verify that a transport can correctly renegotiate mid-stream.
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        self.tc.packetizer.REKEY_BYTES = 16384
        
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)

        self.assertEquals(self.tc.H, self.tc.session_id)
        for i in range(20):
            chan.send('x' * 1024)
        chan.close()
        
        # allow a few seconds for the rekeying to complete
        for i in xrange(50):
            if self.tc.H != self.tc.session_id:
                break
            time.sleep(0.1)
        self.assertNotEquals(self.tc.H, self.tc.session_id)

        schan.close()

    def test_H_compression(self):
        """
        verify that zlib compression is basically working.
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        self.ts.get_security_options().compression = ('zlib',)
        self.tc.get_security_options().compression = ('zlib',)
        event = threading.Event()
        server = NullServer()
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)

        bytes = self.tc.packetizer._Packetizer__sent_bytes
        chan.send('x' * 1024)
        bytes2 = self.tc.packetizer._Packetizer__sent_bytes
        # tests show this is actually compressed to *52 bytes*!  including packet overhead!  nice!! :)
        self.assert_(bytes2 - bytes < 1024)

        chan.close()
        schan.close()
