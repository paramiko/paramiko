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
Some unit tests for the ssh2 protocol in Transport.
"""

from binascii import hexlify, unhexlify
import select
import socket
import sys
import time
import threading
import unittest
import random

from ssh import Transport, SecurityOptions, ServerInterface, RSAKey, DSSKey, \
    SSHException, BadAuthenticationType, InteractiveQuery, ChannelException
from ssh import AUTH_FAILED, AUTH_PARTIALLY_SUCCESSFUL, AUTH_SUCCESSFUL
from ssh import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from ssh.common import MSG_KEXINIT, MSG_CHANNEL_WINDOW_ADJUST
from ssh.message import Message
from loop import LoopSocket


LONG_BANNER = """\
Welcome to the super-fun-land BBS, where our MOTD is the primary thing we
provide. All rights reserved. Offer void in Tennessee. Stunt drivers were
used. Do not attempt at home. Some restrictions apply.

Happy birthday to Commie the cat!

Note: An SSH banner may eventually appear.

Maybe.
"""


class NullServer (ServerInterface):
    paranoid_did_password = False
    paranoid_did_public_key = False
    paranoid_key = DSSKey.from_private_key_file('tests/test_dss.key')
    
    def get_allowed_auths(self, username):
        if username == 'slowdive':
            return 'publickey,password'
        return 'publickey'

    def check_auth_password(self, username, password):
        if (username == 'slowdive') and (password == 'pygmalion'):
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
    
    def check_channel_x11_request(self, channel, single_connection, auth_protocol, auth_cookie, screen_number):
        self._x11_single_connection = single_connection
        self._x11_auth_protocol = auth_protocol
        self._x11_auth_cookie = auth_cookie
        self._x11_screen_number = screen_number
        return True
    
    def check_port_forward_request(self, addr, port):
        self._listen = socket.socket()
        self._listen.bind(('127.0.0.1', 0))
        self._listen.listen(1)
        return self._listen.getsockname()[1]
    
    def cancel_port_forward_request(self, addr, port):
        self._listen.close()
        self._listen = None

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self._tcpip_dest = destination
        return OPEN_SUCCEEDED


class TransportTest (unittest.TestCase):

    assertTrue = unittest.TestCase.failUnless   # for Python 2.3 and below
    assertFalse = unittest.TestCase.failIf      # for Python 2.3 and below

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

    def setup_test_server(self, client_options=None, server_options=None):
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        
        if client_options is not None:
            client_options(self.tc.get_security_options())
        if server_options is not None:
            server_options(self.ts.get_security_options())
        
        event = threading.Event()
        self.server = NullServer()
        self.assert_(not event.isSet())
        self.ts.start_server(event, self.server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())

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
        self.tc.H = unhexlify('0C8307CDE6856FF30BA93684EB0F04C2520E9ED3')
        self.tc.session_id = self.tc.H
        key = self.tc._compute_key('C', 32)
        self.assertEquals('207E66594CA87C44ECCBA3B3CD39FDDB378E6FDB0F97C54B2AA0CFBF900CD995',
                          hexlify(key).upper())

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

    def test_3a_long_banner(self):
        """
        verify that a long banner doesn't mess up the handshake.
        """
        host_key = RSAKey.from_private_key_file('tests/test_rsa.key')
        public_host_key = RSAKey(data=str(host_key))
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assert_(not event.isSet())
        self.socks.send(LONG_BANNER)
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assert_(event.isSet())
        self.assert_(self.ts.is_active())
        
    def test_4_special(self):
        """
        verify that the client can demand odd handshake settings, and can
        renegotiate keys in mid-stream.
        """
        def force_algorithms(options):
            options.ciphers = ('aes256-cbc',)
            options.digests = ('hmac-md5-96',)
        self.setup_test_server(client_options=force_algorithms)
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
        self.setup_test_server()
        self.assertEquals(None, getattr(self.server, '_global_request', None))
        self.tc.set_keepalive(1)
        time.sleep(2)
        self.assertEquals('keepalive@lag.net', self.server._global_request)
        
    def test_6_exec_command(self):
        """
        verify that exec_command() does something reasonable.
        """
        self.setup_test_server()

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

    def test_7_invoke_shell(self):
        """
        verify that invoke_shell() does something reasonable.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)
        chan.send('communist j. cat\n')
        f = schan.makefile()
        self.assertEquals('communist j. cat\n', f.readline())
        chan.close()
        self.assertEquals('', f.readline())

    def test_8_channel_exception(self):
        """
        verify that ChannelException is thrown for a bad open-channel request.
        """
        self.setup_test_server()
        try:
            chan = self.tc.open_channel('bogus')
            self.fail('expected exception')
        except ChannelException, x:
            self.assert_(x.code == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def test_9_exit_status(self):
        """
        verify that get_exit_status() works.
        """
        self.setup_test_server()

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        chan.exec_command('yes')
        schan.send('Hello there.\n')
        self.assert_(not chan.exit_status_ready())
        # trigger an EOF
        schan.shutdown_read()
        schan.shutdown_write()
        schan.send_exit_status(23)
        schan.close()
        
        f = chan.makefile()
        self.assertEquals('Hello there.\n', f.readline())
        self.assertEquals('', f.readline())
        count = 0
        while not chan.exit_status_ready():
            time.sleep(0.1)
            count += 1
            if count > 50:
                raise Exception("timeout")
        self.assertEquals(23, chan.recv_exit_status())
        chan.close()

    def test_A_select(self):
        """
        verify that select() on a channel works.
        """
        self.setup_test_server()
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
        
        # make sure the pipe is still open for now...
        p = chan._pipe
        self.assertEquals(False, p._closed)
        chan.close()
        # ...and now is closed.
        self.assertEquals(True, p._closed)
   
    def test_B_renegotiate(self):
        """
        verify that a transport can correctly renegotiate mid-stream.
        """
        self.setup_test_server()
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

    def test_C_compression(self):
        """
        verify that zlib compression is basically working.
        """
        def force_compression(o):
            o.compression = ('zlib',)
        self.setup_test_server(force_compression, force_compression)
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)

        bytes = self.tc.packetizer._Packetizer__sent_bytes
        chan.send('x' * 1024)
        bytes2 = self.tc.packetizer._Packetizer__sent_bytes
        # tests show this is actually compressed to *52 bytes*!  including packet overhead!  nice!! :)
        self.assert_(bytes2 - bytes < 1024)
        self.assertEquals(52, bytes2 - bytes)

        chan.close()
        schan.close()

    def test_D_x11(self):
        """
        verify that an x11 port can be requested and opened.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        
        requested = []
        def handler(c, (addr, port)):
            requested.append((addr, port))
            self.tc._queue_incoming_channel(c)
            
        self.assertEquals(None, getattr(self.server, '_x11_screen_number', None))
        cookie = chan.request_x11(0, single_connection=True, handler=handler)
        self.assertEquals(0, self.server._x11_screen_number)
        self.assertEquals('MIT-MAGIC-COOKIE-1', self.server._x11_auth_protocol)
        self.assertEquals(cookie, self.server._x11_auth_cookie)
        self.assertEquals(True, self.server._x11_single_connection)
        
        x11_server = self.ts.open_x11_channel(('localhost', 6093))
        x11_client = self.tc.accept()
        self.assertEquals('localhost', requested[0][0])
        self.assertEquals(6093, requested[0][1])
        
        x11_server.send('hello')
        self.assertEquals('hello', x11_client.recv(5))
        
        x11_server.close()
        x11_client.close()
        chan.close()
        schan.close()

    def test_E_reverse_port_forwarding(self):
        """
        verify that a client can ask the server to open a reverse port for
        forwarding.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        
        requested = []
        def handler(c, (origin_addr, origin_port), (server_addr, server_port)):
            requested.append((origin_addr, origin_port))
            requested.append((server_addr, server_port))
            self.tc._queue_incoming_channel(c)
            
        port = self.tc.request_port_forward('127.0.0.1', 0, handler)
        self.assertEquals(port, self.server._listen.getsockname()[1])

        cs = socket.socket()
        cs.connect(('127.0.0.1', port))
        ss, _ = self.server._listen.accept()
        sch = self.ts.open_forwarded_tcpip_channel(ss.getsockname(), ss.getpeername())
        cch = self.tc.accept()
        
        sch.send('hello')
        self.assertEquals('hello', cch.recv(5))
        sch.close()
        cch.close()
        ss.close()
        cs.close()
        
        # now cancel it.
        self.tc.cancel_port_forward('127.0.0.1', port)
        self.assertTrue(self.server._listen is None)

    def test_F_port_forwarding(self):
        """
        verify that a client can forward new connections from a locally-
        forwarded port.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        
        # open a port on the "server" that the client will ask to forward to.
        greeting_server = socket.socket()
        greeting_server.bind(('127.0.0.1', 0))
        greeting_server.listen(1)
        greeting_port = greeting_server.getsockname()[1]

        cs = self.tc.open_channel('direct-tcpip', ('127.0.0.1', greeting_port), ('', 9000))
        sch = self.ts.accept(1.0)
        cch = socket.socket()
        cch.connect(self.server._tcpip_dest)
        
        ss, _ = greeting_server.accept()
        ss.send('Hello!\n')
        ss.close()
        sch.send(cch.recv(8192))
        sch.close()
        
        self.assertEquals('Hello!\n', cs.recv(7))
        cs.close()

    def test_G_stderr_select(self):
        """
        verify that select() on a channel works even if only stderr is
        receiving data.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)

        # nothing should be ready        
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEquals([], r)
        self.assertEquals([], w)
        self.assertEquals([], e)
        
        schan.send_stderr('hello\n')
        
        # something should be ready now (give it 1 second to appear)
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEquals([chan], r)
        self.assertEquals([], w)
        self.assertEquals([], e)

        self.assertEquals('hello\n', chan.recv_stderr(6))
        
        # and, should be dead again now
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEquals([], r)
        self.assertEquals([], w)
        self.assertEquals([], e)

        schan.close()
        chan.close()

    def test_H_send_ready(self):
        """
        verify that send_ready() indicates when a send would not block.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)

        self.assertEquals(chan.send_ready(), True)
        total = 0
        K = '*' * 1024
        while total < 1024 * 1024:
            chan.send(K)
            total += len(K)
            if not chan.send_ready():
                break
        self.assert_(total < 1024 * 1024)

        schan.close()
        chan.close()
        self.assertEquals(chan.send_ready(), True)

    def test_I_rekey_deadlock(self):
        """
        Regression test for deadlock when in-transit messages are received after MSG_KEXINIT is sent
        
        Note: When this test fails, it may leak threads.
        """
        
        # Test for an obscure deadlocking bug that can occur if we receive
        # certain messages while initiating a key exchange.
        #
        # The deadlock occurs as follows:
        #
        # In the main thread:
        #   1. The user's program calls Channel.send(), which sends
        #      MSG_CHANNEL_DATA to the remote host.
        #   2. Packetizer discovers that REKEY_BYTES has been exceeded, and
        #      sets the __need_rekey flag.
        #
        # In the Transport thread:
        #   3. Packetizer notices that the __need_rekey flag is set, and raises
        #      NeedRekeyException.
        #   4. In response to NeedRekeyException, the transport thread sends
        #      MSG_KEXINIT to the remote host.
        # 
        # On the remote host (using any SSH implementation):
        #   5. The MSG_CHANNEL_DATA is received, and MSG_CHANNEL_WINDOW_ADJUST is sent.
        #   6. The MSG_KEXINIT is received, and a corresponding MSG_KEXINIT is sent.
        #
        # In the main thread:
        #   7. The user's program calls Channel.send().
        #   8. Channel.send acquires Channel.lock, then calls Transport._send_user_message().
        #   9. Transport._send_user_message waits for Transport.clear_to_send
        #      to be set (i.e., it waits for re-keying to complete).
        #      Channel.lock is still held.
        #
        # In the Transport thread:
        #   10. MSG_CHANNEL_WINDOW_ADJUST is received; Channel._window_adjust
        #       is called to handle it.
        #   11. Channel._window_adjust tries to acquire Channel.lock, but it
        #       blocks because the lock is already held by the main thread.
        #
        # The result is that the Transport thread never processes the remote
        # host's MSG_KEXINIT packet, because it becomes deadlocked while
        # handling the preceding MSG_CHANNEL_WINDOW_ADJUST message.

        # We set up two separate threads for sending and receiving packets,
        # while the main thread acts as a watchdog timer.  If the timer
        # expires, a deadlock is assumed.

        class SendThread(threading.Thread):
            def __init__(self, chan, iterations, done_event):
                threading.Thread.__init__(self, None, None, self.__class__.__name__)
                self.setDaemon(True)
                self.chan = chan
                self.iterations = iterations
                self.done_event = done_event
                self.watchdog_event = threading.Event()
                self.last = None
            
            def run(self):
                try:
                    for i in xrange(1, 1+self.iterations):
                        if self.done_event.isSet():
                            break
                        self.watchdog_event.set()
                        #print i, "SEND"
                        self.chan.send("x" * 2048)
                finally:
                    self.done_event.set()
                    self.watchdog_event.set()
        
        class ReceiveThread(threading.Thread):
            def __init__(self, chan, done_event):
                threading.Thread.__init__(self, None, None, self.__class__.__name__)
                self.setDaemon(True)
                self.chan = chan
                self.done_event = done_event
                self.watchdog_event = threading.Event()
            
            def run(self):
                try:
                    while not self.done_event.isSet():
                        if self.chan.recv_ready():
                            chan.recv(65536)
                            self.watchdog_event.set()
                        else:
                            if random.randint(0, 1):
                                time.sleep(random.randint(0, 500) / 1000.0)
                finally:
                    self.done_event.set()
                    self.watchdog_event.set()
        
        self.setup_test_server()
        self.ts.packetizer.REKEY_BYTES = 2048
        
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)

        # Monkey patch the client's Transport._handler_table so that the client
        # sends MSG_CHANNEL_WINDOW_ADJUST whenever it receives an initial
        # MSG_KEXINIT.  This is used to simulate the effect of network latency
        # on a real MSG_CHANNEL_WINDOW_ADJUST message.
        self.tc._handler_table = self.tc._handler_table.copy()  # copy per-class dictionary
        _negotiate_keys = self.tc._handler_table[MSG_KEXINIT]
        def _negotiate_keys_wrapper(self, m):
            if self.local_kex_init is None: # Remote side sent KEXINIT
                # Simulate in-transit MSG_CHANNEL_WINDOW_ADJUST by sending it
                # before responding to the incoming MSG_KEXINIT.
                m2 = Message()
                m2.add_byte(chr(MSG_CHANNEL_WINDOW_ADJUST))
                m2.add_int(chan.remote_chanid)
                m2.add_int(1)    # bytes to add
                self._send_message(m2)
            return _negotiate_keys(self, m)
        self.tc._handler_table[MSG_KEXINIT] = _negotiate_keys_wrapper
        
        # Parameters for the test
        iterations = 500    # The deadlock does not happen every time, but it
                            # should after many iterations.
        timeout = 5

        # This event is set when the test is completed
        done_event = threading.Event()

        # Start the sending thread
        st = SendThread(schan, iterations, done_event)
        st.start()
        
        # Start the receiving thread
        rt = ReceiveThread(chan, done_event)
        rt.start()

        # Act as a watchdog timer, checking 
        deadlocked = False
        while not deadlocked and not done_event.isSet():
            for event in (st.watchdog_event, rt.watchdog_event):
                event.wait(timeout)
                if done_event.isSet():
                    break
                if not event.isSet():
                    deadlocked = True
                    break
                event.clear()
        
        # Tell the threads to stop (if they haven't already stopped).  Note
        # that if one or more threads are deadlocked, they might hang around
        # forever (until the process exits).
        done_event.set()

        # Assertion: We must not have detected a timeout.
        self.assertFalse(deadlocked)

        # Close the channels
        schan.close()
        chan.close()
