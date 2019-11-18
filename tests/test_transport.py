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
Some unit tests for the ssh2 protocol in Transport.
"""

from binascii import hexlify
import select
import socket
import time
import threading
import random
import unittest
from mock import Mock

from paramiko import (
    Transport, SecurityOptions, ServerInterface, RSAKey, SSHException,
    ChannelException, Packetizer, AuthHandler, BadHostKeyException
)
from paramiko import AUTH_FAILED, AUTH_SUCCESSFUL
from paramiko import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from paramiko.common import (
    MSG_KEXINIT,
    cMSG_CHANNEL_WINDOW_ADJUST,
    cMSG_UNIMPLEMENTED,
    MIN_PACKET_SIZE,
    MIN_WINDOW_SIZE,
    MAX_WINDOW_SIZE,
    DEFAULT_WINDOW_SIZE,
    DEFAULT_MAX_PACKET_SIZE,
    MSG_USERAUTH_SUCCESS,
)
from paramiko.py3compat import byte_chr
from paramiko.message import Message

from .util import needs_builtin, _support, slow
from .loop import LoopSocket


LONG_BANNER = """\
Welcome to the super-fun-land BBS, where our MOTD is the primary thing we
provide. All rights reserved. Offer void in Tennessee. Stunt drivers were
used. Do not attempt at home. Some restrictions apply.

Happy birthday to Commie the cat!

Note: An SSH banner may eventually appear.

Maybe.
"""


class NullServer (ServerInterface):

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
        if command != b'yes':
            return False
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_global_request(self, kind, msg):
        self._global_request = kind
        # NOTE: for w/e reason, older impl of this returned False always, even
        # tho that's only supposed to occur if the request cannot be served.
        # For now, leaving that the default unless test supplies specific
        # 'acceptable' request kind
        return kind == 'acceptable'

    def check_channel_x11_request(self, channel, single_connection,
                                  auth_protocol, auth_cookie, screen_number):
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


class TransportTest(unittest.TestCase):
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

    def setup_test_server(
        self, client_options=None, server_options=None, connect_kwargs=None,
    ):
        host_key = RSAKey.from_private_key_file(_support('test_rsa.key'))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)

        if client_options is not None:
            client_options(self.tc.get_security_options())
        if server_options is not None:
            server_options(self.ts.get_security_options())

        event = threading.Event()
        self.server = NullServer()
        self.assertTrue(not event.is_set())
        self.ts.start_server(event, self.server)
        if connect_kwargs is None:
            connect_kwargs = dict(
                hostkey=public_host_key,
                username='slowdive',
                password='pygmalion',
            )
        self.tc.connect(**connect_kwargs)
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())

    def test_security_options(self):
        o = self.tc.get_security_options()
        self.assertEqual(type(o), SecurityOptions)
        self.assertTrue(('aes256-cbc', 'blowfish-cbc') != o.ciphers)
        o.ciphers = ('aes256-cbc', 'blowfish-cbc')
        self.assertEqual(('aes256-cbc', 'blowfish-cbc'), o.ciphers)
        try:
            o.ciphers = ('aes256-cbc', 'made-up-cipher')
            self.assertTrue(False)
        except ValueError:
            pass
        try:
            o.ciphers = 23
            self.assertTrue(False)
        except TypeError:
            pass

    def test_security_options_reset(self):
        o = self.tc.get_security_options()
        # should not throw any exceptions
        o.ciphers = o.ciphers
        o.digests = o.digests
        o.key_types = o.key_types
        o.kex = o.kex
        o.compression = o.compression

    def test_compute_key(self):
        self.tc.K = 123281095979686581523377256114209720774539068973101330872763622971399429481072519713536292772709507296759612401802191955568143056534122385270077606457721553469730659233569339356140085284052436697480759510519672848743794433460113118986816826624865291116513647975790797391795651716378444844877749505443714557929  # noqa: E501
        self.tc.H = b'\x0C\x83\x07\xCD\xE6\x85\x6F\xF3\x0B\xA9\x36\x84\xEB\x0F\x04\xC2\x52\x0E\x9E\xD3'  # noqa: E501
        self.tc.session_id = self.tc.H
        key = self.tc._compute_key('C', 32)
        self.assertEqual(b'207E66594CA87C44ECCBA3B3CD39FDDB378E6FDB0F97C54B2AA0CFBF900CD995',
                         hexlify(key).upper())

    def test_simple(self):
        """
        verify that we can establish an ssh link with ourselves across the
        loopback sockets.  this is hardly "simple" but it's simpler than the
        later tests. :)
        """
        host_key = RSAKey.from_private_key_file(_support('test_rsa.key'))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assertTrue(not event.is_set())
        self.assertEqual(None, self.tc.get_username())
        self.assertEqual(None, self.ts.get_username())
        self.assertEqual(False, self.tc.is_authenticated())
        self.assertEqual(False, self.ts.is_authenticated())
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual('slowdive', self.tc.get_username())
        self.assertEqual('slowdive', self.ts.get_username())
        self.assertEqual(True, self.tc.is_authenticated())
        self.assertEqual(True, self.ts.is_authenticated())

    def test_long_banner(self):
        """
        verify that a long banner doesn't mess up the handshake.
        """
        host_key = RSAKey.from_private_key_file(_support('test_rsa.key'))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assertTrue(not event.is_set())
        self.socks.send(LONG_BANNER)
        self.ts.start_server(event, server)
        self.tc.connect(hostkey=public_host_key,
                        username='slowdive', password='pygmalion')
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())

    def test_bad_hostkey(self):
        badkey = RSAKey.from_private_key_file(_support('test_rsa.key'))
        public_badkey = RSAKey(data=badkey.asbytes())
        host_key = RSAKey.from_private_key_file(_support('test_rsa_2k_o.key'),
                                                password='television')
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.ts.start_server(event, server)
        self.assertRaises(
            BadHostKeyException, self.tc.connect,
            hostkey=public_badkey, username='slowdive', password='pygmalion'
        )

    def test_special(self):
        """
        verify that the client can demand odd handshake settings, and can
        renegotiate keys in mid-stream.
        """
        def force_algorithms(options):
            options.ciphers = ('aes256-cbc',)
            options.digests = ('hmac-sha1',)
        self.setup_test_server(client_options=force_algorithms)
        self.assertEqual('aes256-cbc', self.tc.local_cipher)
        self.assertEqual('aes256-cbc', self.tc.remote_cipher)
        self.assertEqual(20, self.tc.packetizer.get_mac_size_out())
        self.assertEqual(20, self.tc.packetizer.get_mac_size_in())

        self.tc.send_ignore(1024)
        self.tc.renegotiate_keys()
        self.ts.send_ignore(1024)

    @slow
    def test_keepalive(self):
        """
        verify that the keepalive will be sent.
        """
        self.setup_test_server()
        self.assertEqual(None, getattr(self.server, '_global_request', None))
        self.tc.set_keepalive(1)
        time.sleep(2)
        self.assertEqual('keepalive@lag.net', self.server._global_request)

    def test_exec_command(self):
        """
        verify that exec_command() does something reasonable.
        """
        self.setup_test_server()

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        try:
            chan.exec_command(b'command contains \xfc and is not a valid UTF-8 string')
            self.assertTrue(False)
        except SSHException:
            pass

        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        f = chan.makefile()
        self.assertEqual('Hello there.\n', f.readline())
        self.assertEqual('', f.readline())
        f = chan.makefile_stderr()
        self.assertEqual('This is on stderr.\n', f.readline())
        self.assertEqual('', f.readline())

        # now try it with combined stdout/stderr
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)
        schan.send('Hello there.\n')
        schan.send_stderr('This is on stderr.\n')
        schan.close()

        chan.set_combine_stderr(True)
        f = chan.makefile()
        self.assertEqual('Hello there.\n', f.readline())
        self.assertEqual('This is on stderr.\n', f.readline())
        self.assertEqual('', f.readline())

    def test_channel_can_be_used_as_context_manager(self):
        """
        verify that exec_command() does something reasonable.
        """
        self.setup_test_server()

        with self.tc.open_session() as chan:
            with self.ts.accept(1.0) as schan:
                chan.exec_command('yes')
                schan.send('Hello there.\n')
                schan.close()

                f = chan.makefile()
                self.assertEqual('Hello there.\n', f.readline())
                self.assertEqual('', f.readline())

    def test_invoke_shell(self):
        """
        verify that invoke_shell() does something reasonable.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)
        chan.send('communist j. cat\n')
        f = schan.makefile()
        self.assertEqual('communist j. cat\n', f.readline())
        chan.close()
        self.assertEqual('', f.readline())

    def test_channel_exception(self):
        """
        verify that ChannelException is thrown for a bad open-channel request.
        """
        self.setup_test_server()
        try:
            _ = self.tc.open_channel('bogus')
            self.fail('expected exception')
        except ChannelException as e:
            self.assertTrue(e.code == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def test_exit_status(self):
        """
        verify that get_exit_status() works.
        """
        self.setup_test_server()

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        chan.exec_command('yes')
        schan.send('Hello there.\n')
        self.assertTrue(not chan.exit_status_ready())
        # trigger an EOF
        schan.shutdown_read()
        schan.shutdown_write()
        schan.send_exit_status(23)
        schan.close()

        f = chan.makefile()
        self.assertEqual('Hello there.\n', f.readline())
        self.assertEqual('', f.readline())
        count = 0
        while not chan.exit_status_ready():
            time.sleep(0.1)
            count += 1
            if count > 50:
                raise Exception("timeout")
        self.assertEqual(23, chan.recv_exit_status())
        chan.close()

    def test_select(self):
        """
        verify that select() on a channel works.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)

        # nothing should be ready
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEqual([], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        schan.send('hello\n')

        # something should be ready now (give it 1 second to appear)
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEqual([chan], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        self.assertEqual(b'hello\n', chan.recv(6))

        # and, should be dead again now
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEqual([], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        schan.close()

        # detect eof?
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEqual([chan], r)
        self.assertEqual([], w)
        self.assertEqual([], e)
        self.assertEqual(bytes(), chan.recv(16))

        # make sure the pipe is still open for now...
        p = chan._pipe
        self.assertEqual(False, p._closed)
        chan.close()
        # ...and now is closed.
        self.assertEqual(True, p._closed)

    def test_renegotiate(self):
        """
        verify that a transport can correctly renegotiate mid-stream.
        """
        self.setup_test_server()
        self.tc.packetizer.REKEY_BYTES = 16384
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)

        self.assertEqual(self.tc.H, self.tc.session_id)
        for i in range(20):
            chan.send('x' * 1024)
        chan.close()

        # allow a few seconds for the rekeying to complete
        for i in range(50):
            if self.tc.H != self.tc.session_id:
                break
            time.sleep(0.1)
        self.assertNotEqual(self.tc.H, self.tc.session_id)

        schan.close()

    def test_compression(self):
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
        block_size = self.tc._cipher_info[self.tc.local_cipher]['block-size']
        mac_size = self.tc._mac_info[self.tc.local_mac]['size']
        # tests show this is actually compressed to *52 bytes*!  including packet overhead!  nice!
        self.assertTrue(bytes2 - bytes < 1024)
        self.assertEqual(16 + block_size + mac_size, bytes2 - bytes)

        chan.close()
        schan.close()

    def test_x11(self):
        """
        verify that an x11 port can be requested and opened.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)

        requested = []

        def handler(c, addr_port):
            addr, port = addr_port
            requested.append((addr, port))
            self.tc._queue_incoming_channel(c)

        self.assertEqual(None, getattr(self.server, '_x11_screen_number', None))
        cookie = chan.request_x11(0, single_connection=True, handler=handler)
        self.assertEqual(0, self.server._x11_screen_number)
        self.assertEqual('MIT-MAGIC-COOKIE-1', self.server._x11_auth_protocol)
        self.assertEqual(cookie, self.server._x11_auth_cookie)
        self.assertEqual(True, self.server._x11_single_connection)

        x11_server = self.ts.open_x11_channel(('localhost', 6093))
        x11_client = self.tc.accept()
        self.assertEqual('localhost', requested[0][0])
        self.assertEqual(6093, requested[0][1])

        x11_server.send('hello')
        self.assertEqual(b'hello', x11_client.recv(5))

        x11_server.close()
        x11_client.close()
        chan.close()
        schan.close()

    def test_reverse_port_forwarding(self):
        """
        verify that a client can ask the server to open a reverse port for
        forwarding.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)  # noqa: F841

        requested = []

        def handler(c, origin_addr_port, server_addr_port):
            requested.append(origin_addr_port)
            requested.append(server_addr_port)
            self.tc._queue_incoming_channel(c)

        port = self.tc.request_port_forward('127.0.0.1', 0, handler)
        self.assertEqual(port, self.server._listen.getsockname()[1])

        cs = socket.socket()
        cs.connect(('127.0.0.1', port))
        ss, _ = self.server._listen.accept()
        sch = self.ts.open_forwarded_tcpip_channel(ss.getsockname(), ss.getpeername())
        cch = self.tc.accept()

        sch.send('hello')
        self.assertEqual(b'hello', cch.recv(5))
        sch.close()
        cch.close()
        ss.close()
        cs.close()

        # now cancel it.
        self.tc.cancel_port_forward('127.0.0.1', port)
        self.assertTrue(self.server._listen is None)

    def test_port_forwarding(self):
        """
        verify that a client can forward new connections from a locally-
        forwarded port.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command('yes')
        schan = self.ts.accept(1.0)  # noqa: F841

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
        ss.send(b'Hello!\n')
        ss.close()
        sch.send(cch.recv(8192))
        sch.close()

        self.assertEqual(b'Hello!\n', cs.recv(7))
        cs.close()

    def test_stderr_select(self):
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
        self.assertEqual([], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        schan.send_stderr('hello\n')

        # something should be ready now (give it 1 second to appear)
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEqual([chan], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        self.assertEqual(b'hello\n', chan.recv_stderr(6))

        # and, should be dead again now
        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEqual([], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        schan.close()
        chan.close()

    def test_send_ready(self):
        """
        verify that send_ready() indicates when a send would not block.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)

        self.assertEqual(chan.send_ready(), True)
        total = 0
        K = '*' * 1024
        limit = 1 + (64 * 2**15)
        while total < limit:
            chan.send(K)
            total += len(K)
            if not chan.send_ready():
                break
        self.assertTrue(total < limit)

        schan.close()
        chan.close()
        self.assertEqual(chan.send_ready(), True)

    def test_rekey_deadlock(self):
        """
        Regression test for deadlock when in-transit messages are received after MSG_KEXINIT sent

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
                    for i in range(1, 1 + self.iterations):
                        if self.done_event.is_set():
                            break
                        self.watchdog_event.set()
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
                    while not self.done_event.is_set():
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
                m2.add_byte(cMSG_CHANNEL_WINDOW_ADJUST)
                m2.add_int(chan.remote_chanid)
                m2.add_int(1)    # bytes to add
                self._send_message(m2)
            return _negotiate_keys(self, m)
        self.tc._handler_table[MSG_KEXINIT] = _negotiate_keys_wrapper

        # Parameters for the test
        iterations = 500    # deadlock should happen after many iterations
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
        while not deadlocked and not done_event.is_set():
            for event in (st.watchdog_event, rt.watchdog_event):
                event.wait(timeout)
                if done_event.is_set():
                    break
                if not event.is_set():
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

    def test_sanitze_packet_size(self):
        """
        verify that we conform to the rfc of packet and window sizes.
        """
        for val, correct in [(4095, MIN_PACKET_SIZE),
                             (None, DEFAULT_MAX_PACKET_SIZE),
                             (2**32, MAX_WINDOW_SIZE)]:
            self.assertEqual(self.tc._sanitize_packet_size(val), correct)

    def test_sanitze_window_size(self):
        """
        verify that we conform to the rfc of packet and window sizes.
        """
        for val, correct in [(32767, MIN_WINDOW_SIZE),
                             (None, DEFAULT_WINDOW_SIZE),
                             (2**32, MAX_WINDOW_SIZE)]:
            self.assertEqual(self.tc._sanitize_window_size(val), correct)

    @slow
    def test_handshake_timeout(self):
        """
        verify that we can get a handshake timeout.
        """
        # Tweak client Transport instance's Packetizer instance so
        # its read_message() sleeps a bit. This helps prevent race conditions
        # where the client Transport's timeout timer thread doesn't even have
        # time to get scheduled before the main client thread finishes
        # handshaking with the server.
        # (Doing this on the server's transport *sounds* more 'correct' but
        # actually doesn't work nearly as well for whatever reason.)
        class SlowPacketizer(Packetizer):
            def read_message(self):
                time.sleep(1)
                return super(SlowPacketizer, self).read_message()
        # NOTE: prettttty sure since the replaced .packetizer Packetizer is now
        # no longer doing anything with its copy of the socket...everything'll
        # be fine. Even tho it's a bit squicky.
        self.tc.packetizer = SlowPacketizer(self.tc.sock)
        # Continue with regular test red tape.
        host_key = RSAKey.from_private_key_file(_support('test_rsa.key'))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assertTrue(not event.is_set())
        self.tc.handshake_timeout = 0.000000000001
        self.ts.start_server(event, server)
        self.assertRaises(EOFError, self.tc.connect,
                          hostkey=public_host_key,
                          username='slowdive',
                          password='pygmalion')

    def test_select_after_close(self):
        """
        verify that select works when a channel is already closed.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)
        schan.close()

        # give client a moment to receive close notification
        time.sleep(0.1)

        r, w, e = select.select([chan], [], [], 0.1)
        self.assertEqual([chan], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

    def test_channel_send_misc(self):
        """
        verify behaviours sending various instances to a channel
        """
        self.setup_test_server()
        text = u"\xa7 slice me nicely"
        with self.tc.open_session() as chan:
            schan = self.ts.accept(1.0)
            if schan is None:
                self.fail("Test server transport failed to accept")
            sfile = schan.makefile()

            # TypeError raised on non string or buffer type
            self.assertRaises(TypeError, chan.send, object())
            self.assertRaises(TypeError, chan.sendall, object())

            # sendall() accepts a unicode instance
            chan.sendall(text)
            expected = text.encode("utf-8")
            self.assertEqual(sfile.read(len(expected)), expected)

    @needs_builtin('buffer')
    def test_channel_send_buffer(self):
        """
        verify sending buffer instances to a channel
        """
        self.setup_test_server()
        data = 3 * b'some test data\n whole'
        with self.tc.open_session() as chan:
            schan = self.ts.accept(1.0)
            if schan is None:
                self.fail("Test server transport failed to accept")
            sfile = schan.makefile()

            # send() accepts buffer instances
            sent = 0
            while sent < len(data):
                sent += chan.send(buffer(data, sent, 8))  # noqa: F821
            self.assertEqual(sfile.read(len(data)), data)

            # sendall() accepts a buffer instance
            chan.sendall(buffer(data))  # noqa: F821
            self.assertEqual(sfile.read(len(data)), data)

    def test_channel_send_memoryview(self):
        """
        verify sending memoryview instances to a channel
        """
        self.setup_test_server()
        data = 3 * b'some test data\n whole'
        with self.tc.open_session() as chan:
            schan = self.ts.accept(1.0)
            if schan is None:
                self.fail("Test server transport failed to accept")
            sfile = schan.makefile()

            # send() accepts memoryview slices
            sent = 0
            view = memoryview(data)
            while sent < len(view):
                sent += chan.send(view[sent:sent + 8])
            self.assertEqual(sfile.read(len(data)), data)

            # sendall() accepts a memoryview instance
            chan.sendall(memoryview(data))
            self.assertEqual(sfile.read(len(data)), data)

    def test_server_rejects_open_channel_without_auth(self):
        try:
            self.setup_test_server(connect_kwargs={})
            self.tc.open_session()
        except ChannelException as e:
            assert e.code == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        else:
            assert False, "Did not raise ChannelException!"

    def test_server_rejects_arbitrary_global_request_without_auth(self):
        self.setup_test_server(connect_kwargs={})
        # NOTE: this dummy global request kind would normally pass muster
        # from the test server.
        self.tc.global_request('acceptable')
        # Global requests never raise exceptions, even on failure (not sure why
        # this was the original design...ugh.) Best we can do to tell failure
        # happened is that the client transport's global_response was set back
        # to None; if it had succeeded, it would be the response Message.
        err = "Unauthed global response incorrectly succeeded!"
        assert self.tc.global_response is None, err

    def test_server_rejects_port_forward_without_auth(self):
        # NOTE: at protocol level port forward requests are treated same as a
        # regular global request, but Paramiko server implements a special-case
        # method for it, so it gets its own test. (plus, THAT actually raises
        # an exception on the client side, unlike the general case...)
        self.setup_test_server(connect_kwargs={})
        try:
            self.tc.request_port_forward('localhost', 1234)
        except SSHException as e:
            assert "forwarding request denied" in str(e)
        else:
            assert False, "Did not raise SSHException!"

    def _send_unimplemented(self, server_is_sender):
        self.setup_test_server()
        sender, recipient = self.tc, self.ts
        if server_is_sender:
            sender, recipient = self.ts, self.tc
        recipient._send_message = Mock()
        msg = Message()
        msg.add_byte(cMSG_UNIMPLEMENTED)
        sender._send_message(msg)
        # TODO: I hate this but I literally don't see a good way to know when
        # the recipient has received the sender's message (there are no
        # existing threading events in play that work for this), esp in this
        # case where we don't WANT a response (as otherwise we could
        # potentially try blocking on the sender's receipt of a reply...maybe).
        time.sleep(0.1)
        assert not recipient._send_message.called

    def test_server_does_not_respond_to_MSG_UNIMPLEMENTED(self):
        self._send_unimplemented(server_is_sender=False)

    def test_client_does_not_respond_to_MSG_UNIMPLEMENTED(self):
        self._send_unimplemented(server_is_sender=True)

    def _send_client_message(self, message_type):
        self.setup_test_server(connect_kwargs={})
        self.ts._send_message = Mock()
        # NOTE: this isn't 100% realistic (most of these message types would
        # have actual other fields in 'em) but it suffices to test the level of
        # message dispatch we're interested in here.
        msg = Message()
        # TODO: really not liking the whole cMSG_XXX vs MSG_XXX duality right
        # now, esp since the former is almost always just byte_chr(the
        # latter)...but since that's the case...
        msg.add_byte(byte_chr(message_type))
        self.tc._send_message(msg)
        # No good way to actually wait for server action (see above tests re:
        # MSG_UNIMPLEMENTED). Grump.
        time.sleep(0.1)

    def _expect_unimplemented(self):
        # Ensure MSG_UNIMPLEMENTED was sent (implies it hit end of loop instead
        # of truly handling the given message).
        # NOTE: When bug present, this will actually be the first thing that
        # fails (since in many cases actual message handling doesn't involve
        # sending a message back right away).
        assert self.ts._send_message.call_count == 1
        reply = self.ts._send_message.call_args[0][0]
        reply.rewind()  # Because it's pre-send, not post-receive
        assert reply.get_byte() == cMSG_UNIMPLEMENTED

    def test_server_transports_reject_client_message_types(self):
        # TODO: handle Transport's own tables too, not just its inner auth
        # handler's table. See TODOs in auth_handler.py
        for message_type in AuthHandler._client_handler_table:
            self._send_client_message(message_type)
            self._expect_unimplemented()
            # Reset for rest of loop
            self.tearDown()
            self.setUp()

    def test_server_rejects_client_MSG_USERAUTH_SUCCESS(self):
        self._send_client_message(MSG_USERAUTH_SUCCESS)
        # Sanity checks
        assert not self.ts.authenticated
        assert not self.ts.auth_handler.authenticated
        # Real fix's behavior
        self._expect_unimplemented()

    def test_transport_channel_close(self):
        """
        verify concurrent channel closing while feeding it with data
        """
        self.setup_test_server()

        def channel_close_thread(chan):
            chan.close()

        threads = []
        for i in range(100):
            chan = self.tc.open_session()
            # trigger internal pipe creation
            chan.fileno()
            t = threading.Thread(target=channel_close_thread, args=(chan,))
            threads.append(t)
            t.start()
            chan._feed(b'')

        for t in threads:
            t.join()
