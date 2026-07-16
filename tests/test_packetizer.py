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

import struct
import sys
import unittest
from hashlib import sha1

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from paramiko import Message, Packetizer, util
from paramiko.common import byte_chr, zero_byte
from paramiko.ssh_exception import SSHException

from ._loop import LoopSocket


x55 = byte_chr(0x55)
x1f = byte_chr(0x1F)


class PacketizerTest(unittest.TestCase):
    def test_write(self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_hexdump(True)
        encryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).encryptor()
        p.set_outbound_cipher(encryptor, 16, sha1, 12, x1f * 20)

        # message has to be at least 16 bytes long, so we'll have at least one
        # block of data encrypted that contains zero random padding bytes
        m = Message()
        m.add_byte(byte_chr(100))
        m.add_int(100)
        m.add_int(1)
        m.add_int(900)
        p.send_message(m)
        data = rsock.recv(100)
        # 32 + 12 bytes of MAC = 44
        self.assertEqual(44, len(data))
        self.assertEqual(
            b"\x43\x91\x97\xbd\x5b\x50\xac\x25\x87\xc2\xc4\x6b\xc7\xe9\x38\xc0",  # noqa
            data[:16],
        )

    def test_read(self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_hexdump(True)
        decryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).decryptor()
        p.set_inbound_cipher(decryptor, 16, sha1, 12, x1f * 20)
        wsock.send(
            b"\x43\x91\x97\xbd\x5b\x50\xac\x25\x87\xc2\xc4\x6b\xc7\xe9\x38\xc0\x90\xd2\x16\x56\x0d\x71\x73\x61\x38\x7c\x4c\x3d\xfb\x97\x7d\xe2\x6e\x03\xb1\xa0\xc2\x1c\xd6\x41\x41\x4c\xb4\x59"  # noqa
        )
        cmd, m = p.read_message()
        self.assertEqual(100, cmd)
        self.assertEqual(100, m.get_int())
        self.assertEqual(1, m.get_int())
        self.assertEqual(900, m.get_int())

    def test_read_rejects_oversized_packet(self):
        # A malicious/corrupt peer could claim an enormous packet_size in
        # the BPP header to force us to allocate huge buffers or block
        # for a long time waiting for that many bytes to arrive. Make sure
        # such a claim is rejected before any of that happens.
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger("paramiko.transport"))

        # No cipher has been configured, so block_size_in is the default
        # (8), and read_message() takes the "older non-ETM" code path.
        # First 4 bytes are the (bogus, oversized) packet length; the rest
        # just pad out to a full block. The length is chosen so it passes
        # the existing block-alignment check and actually exercises the
        # max-size guard (prior to the fix, this value made Paramiko try
        # to read ~4GB from the socket and hang/exhaust memory).
        header = struct.pack(">I", 0xFFFFFFFC) + b"\x00" * 4
        wsock.send(header)
        self.assertRaises(SSHException, p.read_message)

    def test_read_rejects_oversized_packet_etm(self):
        # Same as test_read_rejects_oversized_packet, but for the
        # encrypt-then-mac code path. The bogus length lives in the first
        # 4 bytes of the (unencrypted, under EtM) header, and
        # _check_packet_size() must reject it before read_message() goes
        # on to read "remaining" bytes and verify a MAC.
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_inbound_cipher(
            block_engine=None,
            block_size=8,
            mac_engine=sha1,
            mac_size=12,
            mac_key=x1f * 20,
            etm=True,
        )

        header = struct.pack(">I", 0xFFFFFFFC) + b"\x00" * 4
        wsock.send(header)
        self.assertRaises(SSHException, p.read_message)

    def test_read_rejects_oversized_packet_aead(self):
        # Same as test_read_rejects_oversized_packet, but for the AEAD
        # (eg AES-GCM) code path. The bogus length lives in the first 4
        # bytes of the header, which under GCM is unencrypted ("additional
        # data"); _check_packet_size() must reject it before read_message()
        # goes on to read "remaining" bytes and attempt to decrypt.
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_inbound_cipher(
            block_engine=None,
            block_size=16,
            mac_engine=None,
            mac_size=16,
            mac_key=bytes(),
            aead=True,
            iv_in=x1f * 12,
        )

        header = struct.pack(">I", 0xFFFFFFFC) + b"\x00" * 12
        wsock.send(header)
        self.assertRaises(SSHException, p.read_message)

    def test_closed(self):
        if sys.platform.startswith("win"):  # no SIGALRM on windows
            return
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_hexdump(True)
        encryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).encryptor()
        p.set_outbound_cipher(encryptor, 16, sha1, 12, x1f * 20)

        # message has to be at least 16 bytes long, so we'll have at least one
        # block of data encrypted that contains zero random padding bytes
        m = Message()
        m.add_byte(byte_chr(100))
        m.add_int(100)
        m.add_int(1)
        m.add_int(900)
        wsock.send = lambda x: 0
        from functools import wraps
        import errno
        import os
        import signal

        class TimeoutError(Exception):
            def __init__(self, error_message):
                if hasattr(errno, "ETIME"):
                    self.message = os.sterror(errno.ETIME)
                else:
                    self.messaage = error_message

        def timeout(seconds=1, error_message="Timer expired"):
            def decorator(func):
                def _handle_timeout(signum, frame):
                    raise TimeoutError(error_message)

                def wrapper(*args, **kwargs):
                    signal.signal(signal.SIGALRM, _handle_timeout)
                    signal.alarm(seconds)
                    try:
                        result = func(*args, **kwargs)
                    finally:
                        signal.alarm(0)
                    return result

                return wraps(func)(wrapper)

            return decorator

        send = timeout()(p.send_message)
        self.assertRaises(EOFError, send, m)
