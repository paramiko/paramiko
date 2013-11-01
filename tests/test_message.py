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
Some unit tests for ssh protocol message blocks.
"""

import unittest
from binascii import unhexlify
from paramiko.message import Message
from paramiko.common import *


class MessageTest (unittest.TestCase):

    __a = unhexlify(b('000000170760e09000000001710000000568656c6c6f000003e8')) + (b('x') * 1000)
    __b = unhexlify(b('0100f3003f00000010687565792c64657765792c6c6f756965'))
    __c = unhexlify(b('00000005ff0000000700f5e4d3c2b10900000001110000000700f5e4d3c2b109000000069a1b2c3d4ef7'))
    __d = unhexlify(b('00000005ff000000051122334455ff0000000a00f00000000000000000010000000363617400000003612c62'))

    def test_1_encode(self):
        msg = Message()
        msg.add_int(23)
        msg.add_int(123789456)
        msg.add_string('q')
        msg.add_string('hello')
        msg.add_string('x' * 1000)
        self.assertEquals(msg.asbytes(), self.__a)

        msg = Message()
        msg.add_boolean(True)
        msg.add_boolean(False)
        msg.add_byte(byte_chr(0xf3))

        msg.add_bytes(zero_byte + byte_chr(0x3f))
        msg.add_list(['huey', 'dewey', 'louie'])
        self.assertEquals(msg.asbytes(), self.__b)

        msg = Message()
        msg.add_int64(5)
        msg.add_int64(0xf5e4d3c2b109)
        msg.add_mpint(17)
        msg.add_mpint(0xf5e4d3c2b109)
        msg.add_mpint(-0x65e4d3c2b109)
        self.assertEquals(msg.asbytes(), self.__c)

    def test_2_decode(self):
        msg = Message(self.__a)
        self.assertEquals(msg.get_int(), 23)
        self.assertEquals(msg.get_int(), 123789456)
        self.assertEquals(msg.get_text(), 'q')
        self.assertEquals(msg.get_text(), 'hello')
        self.assertEquals(msg.get_text(), 'x' * 1000)

        msg = Message(self.__b)
        self.assertEquals(msg.get_boolean(), True)
        self.assertEquals(msg.get_boolean(), False)
        self.assertEquals(msg.get_byte(), byte_chr(0xf3))
        self.assertEquals(msg.get_bytes(2), zero_byte + byte_chr(0x3f))
        self.assertEquals(msg.get_list(), ['huey', 'dewey', 'louie'])

        msg = Message(self.__c)
        self.assertEquals(msg.get_int64(), 5)
        self.assertEquals(msg.get_int64(), 0xf5e4d3c2b109)
        self.assertEquals(msg.get_mpint(), 17)
        self.assertEquals(msg.get_mpint(), 0xf5e4d3c2b109)
        self.assertEquals(msg.get_mpint(), -0x65e4d3c2b109)

    def test_3_add(self):
        msg = Message()
        msg.add(5)
        msg.add(0x1122334455)
        msg.add(0xf00000000000000000)
        msg.add(True)
        msg.add('cat')
        msg.add(['a', 'b'])
        self.assertEquals(msg.asbytes(), self.__d)

    def test_4_misc(self):
        msg = Message(self.__d)
        self.assertEquals(msg.get_int(), 5)
        self.assertEquals(msg.get_int(), 0x1122334455)
        self.assertEquals(msg.get_int(), 0xf00000000000000000)
        self.assertEquals(msg.get_so_far(), self.__d[:29])
        self.assertEquals(msg.get_remainder(), self.__d[29:])
        msg.rewind()
        self.assertEquals(msg.get_int(), 5)
        self.assertEquals(msg.get_so_far(), self.__d[:4])
        self.assertEquals(msg.get_remainder(), self.__d[4:])
