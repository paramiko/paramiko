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

import unittest
from binascii import unhexlify
from tests.loop import LoopSocket
from Crypto.Cipher import AES
from Crypto.Hash import SHA, HMAC
from paramiko import Message, Packetizer, util
from paramiko.common import *

x55 = byte_chr(0x55)
x1f = byte_chr(0x1f)


class PacketizerTest (unittest.TestCase):

    def test_1_write (self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger('paramiko.transport'))
        p.set_hexdump(True)
        cipher = AES.new(zero_byte * 16, AES.MODE_CBC, x55 * 16)
        p.set_outbound_cipher(cipher, 16, SHA, 12, x1f * 20)

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
        self.assertEquals(44, len(data))
        self.assertEquals(unhexlify(b('439197bd5b50ac2587c2c46bc7e938c0')), data[:16])

    def test_2_read (self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger('paramiko.transport'))
        p.set_hexdump(True)
        cipher = AES.new(zero_byte * 16, AES.MODE_CBC, x55 * 16)
        p.set_inbound_cipher(cipher, 16, SHA, 12, x1f * 20)
        wsock.send(unhexlify(b('439197bd5b50ac2587c2c46bc7e938c090d216560d717361387c4c3dfb977de26e03b1a0c21cd641414cb459')))
        cmd, m = p.read_message()
        self.assertEquals(100, cmd)
        self.assertEquals(100, m.get_int())
        self.assertEquals(1, m.get_int())
        self.assertEquals(900, m.get_int())
