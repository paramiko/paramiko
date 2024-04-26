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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Some unit tests for the ssh2 protocol in Transport.
"""


from binascii import hexlify
import itertools
import select
import socket
import time
import threading
import random
import unittest
from unittest.mock import Mock

from paramiko import (
    AuthHandler,
    ChannelException,
    IncompatiblePeer,
    MessageOrderError,
    Packetizer,
    RSAKey,
    SSHException,
    SecurityOptions,
    ServiceRequestingTransport,
    Transport,
)
from paramiko.auth_handler import AuthOnlyHandler
from paramiko import OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
from paramiko.common import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_WINDOW_SIZE,
    MAX_WINDOW_SIZE,
    MIN_PACKET_SIZE,
    MIN_WINDOW_SIZE,
    MSG_CHANNEL_OPEN,
    MSG_DEBUG,
    MSG_IGNORE,
    MSG_KEXINIT,
    MSG_UNIMPLEMENTED,
    MSG_USERAUTH_SUCCESS,
    byte_chr,
    cMSG_CHANNEL_WINDOW_ADJUST,
    cMSG_UNIMPLEMENTED,
)
from paramiko.message import Message

from ._util import (
    needs_builtin,
    _support,
    requires_sha1_signing,
    slow,
    server,
    _disable_sha2,
    _disable_sha1,
    TestServer as NullServer,
)
from ._loop import LoopSocket
from pytest import mark, raises


LONG_BANNER = """\
Welcome to the super-fun-land BBS, where our MOTD is the primary thing we
provide. All rights reserved. Offer void in Tennessee. Stunt drivers were
used. Do not attempt at home. Some restrictions apply.

Happy birthday to Commie the cat!

Note: An SSH banner may eventually appear.

Maybe.
"""

# Faux 'packet type' we do not implement and are unlikely ever to (but which is
# technically "within spec" re RFC 4251
MSG_FUGGEDABOUTIT = 253


class TransportTest(unittest.TestCase):
    # TODO: this can get nuked once ServiceRequestingTransport becomes the
    # only Transport, as it has this baked in.
    _auth_handler_class = AuthHandler

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

    # TODO: unify with newer contextmanager
    def setup_test_server(
        self, client_options=None, server_options=None, connect_kwargs=None
    ):
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
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
                username="slowdive",
                password="pygmalion",
            )
        self.tc.connect(**connect_kwargs)
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())

    def test_security_options(self):
        o = self.tc.get_security_options()
        self.assertEqual(type(o), SecurityOptions)
        self.assertTrue(("aes256-cbc", "aes192-cbc") != o.ciphers)
        o.ciphers = ("aes256-cbc", "aes192-cbc")
        self.assertEqual(("aes256-cbc", "aes192-cbc"), o.ciphers)
        try:
            o.ciphers = ("aes256-cbc", "made-up-cipher")
            self.assertTrue(False)
        except ValueError:
            pass
        try:
            o.ciphers = 23
            self.assertTrue(False)
        except TypeError:
            pass

    def testb_security_options_reset(self):
        o = self.tc.get_security_options()
        # should not throw any exceptions
        o.ciphers = o.ciphers
        o.digests = o.digests
        o.key_types = o.key_types
        o.kex = o.kex
        o.compression = o.compression

    def test_compute_key(self):
        self.tc.K = 123281095979686581523377256114209720774539068973101330872763622971399429481072519713536292772709507296759612401802191955568143056534122385270077606457721553469730659233569339356140085284052436697480759510519672848743794433460113118986816826624865291116513647975790797391795651716378444844877749505443714557929  # noqa
        self.tc.H = b"\x0C\x83\x07\xCD\xE6\x85\x6F\xF3\x0B\xA9\x36\x84\xEB\x0F\x04\xC2\x52\x0E\x9E\xD3"  # noqa
        self.tc.session_id = self.tc.H
        key = self.tc._compute_key("C", 32)
        self.assertEqual(
            b"207E66594CA87C44ECCBA3B3CD39FDDB378E6FDB0F97C54B2AA0CFBF900CD995",  # noqa
            hexlify(key).upper(),
        )

    def test_simple(self):
        """
        verify that we can establish an ssh link with ourselves across the
        loopback sockets.  this is hardly "simple" but it's simpler than the
        later tests. :)
        """
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
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
        self.tc.connect(
            hostkey=public_host_key, username="slowdive", password="pygmalion"
        )
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual("slowdive", self.tc.get_username())
        self.assertEqual("slowdive", self.ts.get_username())
        self.assertEqual(True, self.tc.is_authenticated())
        self.assertEqual(True, self.ts.is_authenticated())

    def test_long_banner(self):
        """
        verify that a long banner doesn't mess up the handshake.
        """
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assertTrue(not event.is_set())
        self.socks.send(LONG_BANNER)
        self.ts.start_server(event, server)
        self.tc.connect(
            hostkey=public_host_key, username="slowdive", password="pygmalion"
        )
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())

    def test_special(self):
        """
        verify that the client can demand odd handshake settings, and can
        renegotiate keys in mid-stream.
        """

        def force_algorithms(options):
            options.ciphers = ("aes256-cbc",)
            options.digests = ("hmac-md5-96",)

        self.setup_test_server(client_options=force_algorithms)
        self.assertEqual("aes256-cbc", self.tc.local_cipher)
        self.assertEqual("aes256-cbc", self.tc.remote_cipher)
        self.assertEqual(12, self.tc.packetizer.get_mac_size_out())
        self.assertEqual(12, self.tc.packetizer.get_mac_size_in())

        self.tc.send_ignore(1024)
        self.tc.renegotiate_keys()
        self.ts.send_ignore(1024)

    @slow
    def test_keepalive(self):
        """
        verify that the keepalive will be sent.
        """
        self.setup_test_server()
        self.assertEqual(None, getattr(self.server, "_global_request", None))
        self.tc.set_keepalive(1)
        time.sleep(2)
        self.assertEqual("keepalive@lag.net", self.server._global_request)

    def test_exec_command(self):
        """
        verify that exec_command() does something reasonable.
        """
        self.setup_test_server()

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        try:
            chan.exec_command(
                b"command contains \xfc and is not a valid UTF-8 string"
            )
            self.assertTrue(False)
        except SSHException:
            pass

        chan = self.tc.open_session()
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)
        schan.send("Hello there.\n")
        schan.send_stderr("This is on stderr.\n")
        schan.close()

        f = chan.makefile()
        self.assertEqual("Hello there.\n", f.readline())
        self.assertEqual("", f.readline())
        f = chan.makefile_stderr()
        self.assertEqual("This is on stderr.\n", f.readline())
        self.assertEqual("", f.readline())

        # now try it with combined stdout/stderr
        chan = self.tc.open_session()
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)
        schan.send("Hello there.\n")
        schan.send_stderr("This is on stderr.\n")
        schan.close()

        chan.set_combine_stderr(True)
        f = chan.makefile()
        self.assertEqual("Hello there.\n", f.readline())
        self.assertEqual("This is on stderr.\n", f.readline())
        self.assertEqual("", f.readline())

    def test_channel_can_be_used_as_context_manager(self):
        """
        verify that exec_command() does something reasonable.
        """
        self.setup_test_server()

        with self.tc.open_session() as chan:
            with self.ts.accept(1.0) as schan:
                chan.exec_command("yes")
                schan.send("Hello there.\n")
                schan.close()

                f = chan.makefile()
                self.assertEqual("Hello there.\n", f.readline())
                self.assertEqual("", f.readline())

    def test_invoke_shell(self):
        """
        verify that invoke_shell() does something reasonable.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.invoke_shell()
        schan = self.ts.accept(1.0)
        chan.send("communist j. cat\n")
        f = schan.makefile()
        self.assertEqual("communist j. cat\n", f.readline())
        chan.close()
        self.assertEqual("", f.readline())

    def test_channel_exception(self):
        """
        verify that ChannelException is thrown for a bad open-channel request.
        """
        self.setup_test_server()
        try:
            self.tc.open_channel("bogus")
            self.fail("expected exception")
        except ChannelException as e:
            self.assertTrue(e.code == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def test_exit_status(self):
        """
        verify that get_exit_status() works.
        """
        self.setup_test_server()

        chan = self.tc.open_session()
        schan = self.ts.accept(1.0)
        chan.exec_command("yes")
        schan.send("Hello there.\n")
        self.assertTrue(not chan.exit_status_ready())
        # trigger an EOF
        schan.shutdown_read()
        schan.shutdown_write()
        schan.send_exit_status(23)
        schan.close()

        f = chan.makefile()
        self.assertEqual("Hello there.\n", f.readline())
        self.assertEqual("", f.readline())
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

        schan.send("hello\n")

        # something should be ready now (give it 1 second to appear)
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEqual([chan], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        self.assertEqual(b"hello\n", chan.recv(6))

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
        self.assertEqual(b"", chan.recv(16))

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
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)

        self.assertEqual(self.tc.H, self.tc.session_id)
        for i in range(20):
            chan.send("x" * 1024)
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
            o.compression = ("zlib",)

        self.setup_test_server(force_compression, force_compression)
        chan = self.tc.open_session()
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)

        bytes = self.tc.packetizer._Packetizer__sent_bytes
        chan.send("x" * 1024)
        bytes2 = self.tc.packetizer._Packetizer__sent_bytes
        block_size = self.tc._cipher_info[self.tc.local_cipher]["block-size"]
        mac_size = self.tc._mac_info[self.tc.local_mac]["size"]
        # tests show this is actually compressed to *52 bytes*!  including
        # packet overhead!  nice!! :)
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
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)

        requested = []

        def handler(c, addr_port):
            addr, port = addr_port
            requested.append((addr, port))
            self.tc._queue_incoming_channel(c)

        self.assertEqual(
            None, getattr(self.server, "_x11_screen_number", None)
        )
        cookie = chan.request_x11(0, single_connection=True, handler=handler)
        self.assertEqual(0, self.server._x11_screen_number)
        self.assertEqual("MIT-MAGIC-COOKIE-1", self.server._x11_auth_protocol)
        self.assertEqual(cookie, self.server._x11_auth_cookie)
        self.assertEqual(True, self.server._x11_single_connection)

        x11_server = self.ts.open_x11_channel(("localhost", 6093))
        x11_client = self.tc.accept()
        self.assertEqual("localhost", requested[0][0])
        self.assertEqual(6093, requested[0][1])

        x11_server.send("hello")
        self.assertEqual(b"hello", x11_client.recv(5))

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
        chan.exec_command("yes")
        self.ts.accept(1.0)

        requested = []

        def handler(c, origin_addr_port, server_addr_port):
            requested.append(origin_addr_port)
            requested.append(server_addr_port)
            self.tc._queue_incoming_channel(c)

        port = self.tc.request_port_forward("127.0.0.1", 0, handler)
        self.assertEqual(port, self.server._listen.getsockname()[1])

        cs = socket.socket()
        cs.connect(("127.0.0.1", port))
        ss, _ = self.server._listen.accept()
        sch = self.ts.open_forwarded_tcpip_channel(
            ss.getsockname(), ss.getpeername()
        )
        cch = self.tc.accept()

        sch.send("hello")
        self.assertEqual(b"hello", cch.recv(5))
        sch.close()
        cch.close()
        ss.close()
        cs.close()

        # now cancel it.
        self.tc.cancel_port_forward("127.0.0.1", port)
        self.assertTrue(self.server._listen is None)

    def test_port_forwarding(self):
        """
        verify that a client can forward new connections from a locally-
        forwarded port.
        """
        self.setup_test_server()
        chan = self.tc.open_session()
        chan.exec_command("yes")
        self.ts.accept(1.0)

        # open a port on the "server" that the client will ask to forward to.
        greeting_server = socket.socket()
        greeting_server.bind(("127.0.0.1", 0))
        greeting_server.listen(1)
        greeting_port = greeting_server.getsockname()[1]

        cs = self.tc.open_channel(
            "direct-tcpip", ("127.0.0.1", greeting_port), ("", 9000)
        )
        sch = self.ts.accept(1.0)
        cch = socket.socket()
        cch.connect(self.server._tcpip_dest)

        ss, _ = greeting_server.accept()
        ss.send(b"Hello!\n")
        ss.close()
        sch.send(cch.recv(8192))
        sch.close()

        self.assertEqual(b"Hello!\n", cs.recv(7))
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

        schan.send_stderr("hello\n")

        # something should be ready now (give it 1 second to appear)
        for i in range(10):
            r, w, e = select.select([chan], [], [], 0.1)
            if chan in r:
                break
            time.sleep(0.1)
        self.assertEqual([chan], r)
        self.assertEqual([], w)
        self.assertEqual([], e)

        self.assertEqual(b"hello\n", chan.recv_stderr(6))

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
        K = "*" * 1024
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
        Regression test for deadlock when in-transit messages are received
        after MSG_KEXINIT is sent

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
        #   5. The MSG_CHANNEL_DATA is received, and MSG_CHANNEL_WINDOW_ADJUST
        #      is sent.
        #   6. The MSG_KEXINIT is received, and a corresponding MSG_KEXINIT is
        #      sent.
        #
        # In the main thread:
        #   7. The user's program calls Channel.send().
        #   8. Channel.send acquires Channel.lock, then calls
        #      Transport._send_user_message().
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
                threading.Thread.__init__(
                    self, None, None, self.__class__.__name__
                )
                self.daemon = True
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
                        # print i, "SEND"
                        self.chan.send("x" * 2048)
                finally:
                    self.done_event.set()
                    self.watchdog_event.set()

        class ReceiveThread(threading.Thread):
            def __init__(self, chan, done_event):
                threading.Thread.__init__(
                    self, None, None, self.__class__.__name__
                )
                self.daemon = True
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
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)

        # Monkey patch the client's Transport._handler_table so that the client
        # sends MSG_CHANNEL_WINDOW_ADJUST whenever it receives an initial
        # MSG_KEXINIT.  This is used to simulate the effect of network latency
        # on a real MSG_CHANNEL_WINDOW_ADJUST message.
        self.tc._handler_table = (
            self.tc._handler_table.copy()
        )  # copy per-class dictionary
        _negotiate_keys = self.tc._handler_table[MSG_KEXINIT]

        def _negotiate_keys_wrapper(self, m):
            if self.local_kex_init is None:  # Remote side sent KEXINIT
                # Simulate in-transit MSG_CHANNEL_WINDOW_ADJUST by sending it
                # before responding to the incoming MSG_KEXINIT.
                m2 = Message()
                m2.add_byte(cMSG_CHANNEL_WINDOW_ADJUST)
                m2.add_int(chan.remote_chanid)
                m2.add_int(1)  # bytes to add
                self._send_message(m2)
            return _negotiate_keys(self, m)

        self.tc._handler_table[MSG_KEXINIT] = _negotiate_keys_wrapper

        # Parameters for the test
        iterations = 500  # The deadlock does not happen every time, but it
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
        for val, correct in [
            (4095, MIN_PACKET_SIZE),
            (None, DEFAULT_MAX_PACKET_SIZE),
            (2**32, MAX_WINDOW_SIZE),
        ]:
            self.assertEqual(self.tc._sanitize_packet_size(val), correct)

    def test_sanitze_window_size(self):
        """
        verify that we conform to the rfc of packet and window sizes.
        """
        for val, correct in [
            (32767, MIN_WINDOW_SIZE),
            (None, DEFAULT_WINDOW_SIZE),
            (2**32, MAX_WINDOW_SIZE),
        ]:
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
                return super().read_message()

        # NOTE: prettttty sure since the replaced .packetizer Packetizer is now
        # no longer doing anything with its copy of the socket...everything'll
        # be fine. Even tho it's a bit squicky.
        self.tc.packetizer = SlowPacketizer(self.tc.sock)
        # Continue with regular test red tape.
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        public_host_key = RSAKey(data=host_key.asbytes())
        self.ts.add_server_key(host_key)
        event = threading.Event()
        server = NullServer()
        self.assertTrue(not event.is_set())
        self.tc.handshake_timeout = 0.000000000001
        self.ts.start_server(event, server)
        self.assertRaises(
            EOFError,
            self.tc.connect,
            hostkey=public_host_key,
            username="slowdive",
            password="pygmalion",
        )

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
        text = "\xa7 slice me nicely"
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

    @needs_builtin("buffer")
    def test_channel_send_buffer(self):
        """
        verify sending buffer instances to a channel
        """
        self.setup_test_server()
        data = 3 * b"some test data\n whole"
        with self.tc.open_session() as chan:
            schan = self.ts.accept(1.0)
            if schan is None:
                self.fail("Test server transport failed to accept")
            sfile = schan.makefile()

            # send() accepts buffer instances
            sent = 0
            while sent < len(data):
                sent += chan.send(buffer(data, sent, 8))  # noqa
            self.assertEqual(sfile.read(len(data)), data)

            # sendall() accepts a buffer instance
            chan.sendall(buffer(data))  # noqa
            self.assertEqual(sfile.read(len(data)), data)

    @needs_builtin("memoryview")
    def test_channel_send_memoryview(self):
        """
        verify sending memoryview instances to a channel
        """
        self.setup_test_server()
        data = 3 * b"some test data\n whole"
        with self.tc.open_session() as chan:
            schan = self.ts.accept(1.0)
            if schan is None:
                self.fail("Test server transport failed to accept")
            sfile = schan.makefile()

            # send() accepts memoryview slices
            sent = 0
            view = memoryview(data)
            while sent < len(view):
                sent += chan.send(view[sent : sent + 8])
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
        self.tc.global_request("acceptable")
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
            self.tc.request_port_forward("localhost", 1234)
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
        some_handler = self._auth_handler_class(self.tc)
        for message_type in some_handler._client_handler_table:
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

    def test_can_override_packetizer_used(self):
        class MyPacketizer(Packetizer):
            pass

        # control case
        assert Transport(sock=LoopSocket()).packetizer.__class__ is Packetizer
        # overridden case
        tweaked = Transport(sock=LoopSocket(), packetizer_class=MyPacketizer)
        assert tweaked.packetizer.__class__ is MyPacketizer


# TODO: for now this is purely a regression test. It needs actual tests of the
# intentional new behavior too!
class ServiceRequestingTransportTest(TransportTest):
    _auth_handler_class = AuthOnlyHandler

    def setUp(self):
        # Copypasta (Transport init is load-bearing)
        self.socks = LoopSocket()
        self.sockc = LoopSocket()
        self.sockc.link(self.socks)
        # New class who dis
        self.tc = ServiceRequestingTransport(self.sockc)
        self.ts = ServiceRequestingTransport(self.socks)


class AlgorithmDisablingTests(unittest.TestCase):
    def test_preferred_lists_default_to_private_attribute_contents(self):
        t = Transport(sock=Mock())
        assert t.preferred_ciphers == t._preferred_ciphers
        assert t.preferred_macs == t._preferred_macs
        assert t.preferred_keys == tuple(
            t._preferred_keys
            + tuple(
                "{}-cert-v01@openssh.com".format(x) for x in t._preferred_keys
            )
        )
        assert t.preferred_kex == t._preferred_kex

    def test_preferred_lists_filter_disabled_algorithms(self):
        t = Transport(
            sock=Mock(),
            disabled_algorithms={
                "ciphers": ["aes128-cbc"],
                "macs": ["hmac-md5"],
                "keys": ["ssh-dss"],
                "kex": ["diffie-hellman-group14-sha256"],
            },
        )
        assert "aes128-cbc" in t._preferred_ciphers
        assert "aes128-cbc" not in t.preferred_ciphers
        assert "hmac-md5" in t._preferred_macs
        assert "hmac-md5" not in t.preferred_macs
        assert "ssh-dss" in t._preferred_keys
        assert "ssh-dss" not in t.preferred_keys
        assert "ssh-dss-cert-v01@openssh.com" not in t.preferred_keys
        assert "diffie-hellman-group14-sha256" in t._preferred_kex
        assert "diffie-hellman-group14-sha256" not in t.preferred_kex

    def test_implementation_refers_to_public_algo_lists(self):
        t = Transport(
            sock=Mock(),
            disabled_algorithms={
                "ciphers": ["aes128-cbc"],
                "macs": ["hmac-md5"],
                "keys": ["ssh-dss"],
                "kex": ["diffie-hellman-group14-sha256"],
                "compression": ["zlib"],
            },
        )
        # Enable compression cuz otherwise disabling one option for it makes no
        # sense...
        t.use_compression(True)
        # Effectively a random spot check, but kex init touches most/all of the
        # algorithm lists so it's a good spot.
        t._send_message = Mock()
        t._send_kex_init()
        # Cribbed from Transport._parse_kex_init, which didn't feel worth
        # refactoring given all the vars involved :(
        m = t._send_message.call_args[0][0]
        m.rewind()
        m.get_byte()  # the msg type
        m.get_bytes(16)  # cookie, discarded
        kexen = m.get_list()
        server_keys = m.get_list()
        ciphers = m.get_list()
        m.get_list()
        macs = m.get_list()
        m.get_list()
        compressions = m.get_list()
        # OK, now we can actually check that our disabled algos were not
        # included (as this message includes the full lists)
        assert "aes128-cbc" not in ciphers
        assert "hmac-md5" not in macs
        assert "ssh-dss" not in server_keys
        assert "diffie-hellman-group14-sha256" not in kexen
        assert "zlib" not in compressions


class TestSHA2SignatureKeyExchange(unittest.TestCase):
    # NOTE: these all rely on the default server() hostkey being RSA
    # NOTE: these rely on both sides being properly implemented re: agreed-upon
    # hostkey during kex being what's actually used. Truly proving that eg
    # SHA512 was used, is quite difficult w/o super gross hacks. However, there
    # are new tests in test_pkey.py which use known signature blobs to prove
    # the SHA2 family was in fact used!

    @requires_sha1_signing
    def test_base_case_ssh_rsa_still_used_as_fallback(self):
        # Prove that ssh-rsa is used if either, or both, participants have SHA2
        # algorithms disabled
        for which in ("init", "client_init", "server_init"):
            with server(**{which: _disable_sha2}) as (tc, _):
                assert tc.host_key_type == "ssh-rsa"

    def test_kex_with_sha2_512(self):
        # It's the default!
        with server() as (tc, _):
            assert tc.host_key_type == "rsa-sha2-512"

    def test_kex_with_sha2_256(self):
        # No 512 -> you get 256
        with server(
            init=dict(disabled_algorithms=dict(keys=["rsa-sha2-512"]))
        ) as (tc, _):
            assert tc.host_key_type == "rsa-sha2-256"

    def _incompatible_peers(self, client_init, server_init):
        with server(
            client_init=client_init, server_init=server_init, catch_error=True
        ) as (tc, ts, err):
            # If neither side blew up then that's bad!
            assert err is not None
            # If client side blew up first, it'll be straightforward
            if isinstance(err, IncompatiblePeer):
                pass
            # If server side blew up first, client sees EOF & we need to check
            # the server transport for its saved error (otherwise it can only
            # appear in log output)
            elif isinstance(err, EOFError):
                assert ts.saved_exception is not None
                assert isinstance(ts.saved_exception, IncompatiblePeer)
            # If it was something else, welp
            else:
                raise err

    def test_client_sha2_disabled_server_sha1_disabled_no_match(self):
        self._incompatible_peers(
            client_init=_disable_sha2, server_init=_disable_sha1
        )

    def test_client_sha1_disabled_server_sha2_disabled_no_match(self):
        self._incompatible_peers(
            client_init=_disable_sha1, server_init=_disable_sha2
        )

    def test_explicit_client_hostkey_not_limited(self):
        # Be very explicit about the hostkey on BOTH ends,
        # and ensure it still ends up choosing sha2-512.
        # (This is a regression test vs previous implementation which overwrote
        # the entire preferred-hostkeys structure when given an explicit key as
        # a client.)
        hostkey = RSAKey.from_private_key_file(_support("rsa.key"))
        connect = dict(
            hostkey=hostkey, username="slowdive", password="pygmalion"
        )
        with server(hostkey=hostkey, connect=connect) as (tc, _):
            assert tc.host_key_type == "rsa-sha2-512"


class TestExtInfo(unittest.TestCase):
    def test_ext_info_handshake_exposed_in_client_kexinit(self):
        with server() as (tc, _):
            # NOTE: this is latest KEXINIT /sent by us/ (Transport retains it)
            kex = tc._get_latest_kex_init()
            # flag in KexAlgorithms list
            assert "ext-info-c" in kex["kex_algo_list"]
            # data stored on Transport after hearing back from a compatible
            # server (such as ourselves in server mode)
            assert tc.server_extensions == {
                "server-sig-algs": b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss"  # noqa
            }

    def test_client_uses_server_sig_algs_for_pubkey_auth(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            server_init=dict(
                disabled_algorithms=dict(pubkeys=["rsa-sha2-512"])
            ),
        ) as (tc, _):
            assert tc.is_authenticated()
            # Client settled on 256 despite itself not having 512 disabled (and
            # otherwise, 512 would have been earlier in the preferred list)
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"


class BadSeqPacketizer(Packetizer):
    def read_message(self):
        cmd, msg = super().read_message()
        # Only mess w/ seqno if kexinit.
        if cmd is MSG_KEXINIT:
            # NOTE: this is /only/ the copy of the seqno which gets
            # transmitted up from Packetizer; it's not modifying
            # Packetizer's own internal seqno. For these tests,
            # modifying the latter isn't required, and is also harder
            # to do w/o triggering MAC mismatches.
            msg.seqno = 17  # arbitrary nonzero int
        return cmd, msg


class TestStrictKex:
    def test_kex_algos_includes_kex_strict_c(self):
        with server() as (tc, _):
            kex = tc._get_latest_kex_init()
            assert "kex-strict-c-v00@openssh.com" in kex["kex_algo_list"]

    @mark.parametrize(
        "server_active,client_active",
        itertools.product([True, False], repeat=2),
    )
    def test_mode_agreement(self, server_active, client_active):
        with server(
            server_init=dict(strict_kex=server_active),
            client_init=dict(strict_kex=client_active),
        ) as (tc, ts):
            if server_active and client_active:
                assert tc.agreed_on_strict_kex is True
                assert ts.agreed_on_strict_kex is True
            else:
                assert tc.agreed_on_strict_kex is False
                assert ts.agreed_on_strict_kex is False

    def test_mode_advertised_by_default(self):
        # NOTE: no explicit strict_kex overrides...
        with server() as (tc, ts):
            assert all(
                (
                    tc.advertise_strict_kex,
                    tc.agreed_on_strict_kex,
                    ts.advertise_strict_kex,
                    ts.agreed_on_strict_kex,
                )
            )

    @mark.parametrize(
        "ptype",
        (
            # "normal" but definitely out-of-order message
            MSG_CHANNEL_OPEN,
            # Normally ignored, but not in this case
            MSG_IGNORE,
            # Normally triggers debug parsing, but not in this case
            MSG_DEBUG,
            # Normally ignored, but...you get the idea
            MSG_UNIMPLEMENTED,
            # Not real, so would normally trigger us /sending/
            # MSG_UNIMPLEMENTED, but...
            MSG_FUGGEDABOUTIT,
        ),
    )
    def test_MessageOrderError_non_kex_messages_in_initial_kex(self, ptype):
        class AttackTransport(Transport):
            # Easiest apparent spot on server side which is:
            # - late enough for both ends to have handshook on strict mode
            # - early enough to be in the window of opportunity for Terrapin
            # attack; essentially during actual kex, when the engine is
            # waiting for things like MSG_KEXECDH_REPLY (for eg curve25519).
            def _negotiate_keys(self, m):
                self.clear_to_send_lock.acquire()
                try:
                    self.clear_to_send.clear()
                finally:
                    self.clear_to_send_lock.release()
                if self.local_kex_init is None:
                    # remote side wants to renegotiate
                    self._send_kex_init()
                self._parse_kex_init(m)
                # Here, we would normally kick over to kex_engine, but instead
                # we want the server to send the OOO message.
                m = Message()
                m.add_byte(byte_chr(ptype))
                # rest of packet unnecessary...
                self._send_message(m)

        with raises(MessageOrderError):
            with server(server_transport_factory=AttackTransport) as (tc, _):
                pass  # above should run and except during connect()

    def test_SSHException_raised_on_out_of_order_messages_when_not_strict(
        self,
    ):
        # This is kind of dumb (either situation is still fatal!) but whatever,
        # may as well be strict with our new strict flag...
        with raises(SSHException) as info:  # would be true either way, but
            with server(
                client_init=dict(strict_kex=False),
            ) as (tc, _):
                tc._expect_packet(MSG_KEXINIT)
                tc.open_session()
        assert info.type is SSHException  # NOT MessageOrderError!

    def test_error_not_raised_when_kexinit_not_seq_0_but_unstrict(self):
        with server(
            client_init=dict(
                # Disable strict kex
                strict_kex=False,
                # Give our clientside a packetizer that sets all kexinit
                # Message objects to have .seqno==17, which would trigger the
                # new logic if we'd forgotten to wrap it in strict-kex check
                packetizer_class=BadSeqPacketizer,
            ),
        ):
            pass  # kexinit happens at connect...

    def test_MessageOrderError_raised_when_kexinit_not_seq_0_and_strict(self):
        with raises(MessageOrderError):
            with server(
                # Give our clientside a packetizer that sets all kexinit
                # Message objects to have .seqno==17, which should trigger the
                # new logic (given we are NOT disabling strict-mode)
                client_init=dict(packetizer_class=BadSeqPacketizer),
            ):
                pass  # kexinit happens at connect...

    def test_sequence_numbers_reset_on_newkeys_when_strict(self):
        with server(defer=True) as (tc, ts):
            # When in strict mode, these should all be zero or close to it
            # (post-kexinit, pre-auth).
            # Server->client will be 1 (EXT_INFO got sent after NEWKEYS)
            assert tc.packetizer._Packetizer__sequence_number_in == 1
            assert ts.packetizer._Packetizer__sequence_number_out == 1
            # Client->server will be 0
            assert tc.packetizer._Packetizer__sequence_number_out == 0
            assert ts.packetizer._Packetizer__sequence_number_in == 0

    def test_sequence_numbers_not_reset_on_newkeys_when_not_strict(self):
        with server(defer=True, client_init=dict(strict_kex=False)) as (
            tc,
            ts,
        ):
            # When not in strict mode, these will all be ~3-4 or so
            # (post-kexinit, pre-auth). Not encoding exact values as it will
            # change anytime we mess with the test harness...
            assert tc.packetizer._Packetizer__sequence_number_in != 0
            assert tc.packetizer._Packetizer__sequence_number_out != 0
            assert ts.packetizer._Packetizer__sequence_number_in != 0
            assert ts.packetizer._Packetizer__sequence_number_out != 0

    def test_sequence_number_rollover_detected(self):
        class RolloverTransport(Transport):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                # Induce an about-to-rollover seqno, such that it rolls over
                # during initial kex. (Sequence numbers are uint32, so we need
                # the largest possible 32bit integer such that incrementing it
                # will roll over to 0.)
                last_seq = 2**32 - 1
                setattr(
                    self.packetizer,
                    "_Packetizer__sequence_number_in",
                    last_seq,
                )
                setattr(
                    self.packetizer,
                    "_Packetizer__sequence_number_out",
                    last_seq,
                )

        with raises(
            SSHException,
            match=r"Sequence number rolled over during initial kex!",
        ):
            with server(
                client_init=dict(
                    # Disable strict kex - this should happen always
                    strict_kex=False,
                ),
                # Transport which tickles its packetizer seqno's
                transport_factory=RolloverTransport,
            ):
                pass  # kexinit happens at connect...
