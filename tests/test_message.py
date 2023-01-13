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
Some unit tests for ssh protocol message blocks.
"""

import unittest

from paramiko.message import Message
from paramiko.common import byte_chr, zero_byte


class MessageTest(unittest.TestCase):

    __a = (
        b"\x00\x00\x00\x17\x07\x60\xe0\x90\x00\x00\x00\x01\x71\x00\x00\x00\x05\x68\x65\x6c\x6c\x6f\x00\x00\x03\xe8"  # noqa
        + b"x" * 1000
    )
    __b = b"\x01\x00\xf3\x00\x3f\x00\x00\x00\x10\x68\x75\x65\x79\x2c\x64\x65\x77\x65\x79\x2c\x6c\x6f\x75\x69\x65"  # noqa
    __c = b"\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\xf5\xe4\xd3\xc2\xb1\x09\x00\x00\x00\x01\x11\x00\x00\x00\x07\x00\xf5\xe4\xd3\xc2\xb1\x09\x00\x00\x00\x06\x9a\x1b\x2c\x3d\x4e\xf7"  # noqa
    __d = b"\x00\x00\x00\x05\xff\x00\x00\x00\x05\x11\x22\x33\x44\x55\xff\x00\x00\x00\x0a\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x63\x61\x74\x00\x00\x00\x03\x61\x2c\x62"  # noqa

    def test_encode(self):
        msg = Message()
        msg.add_int(23)
        msg.add_int(123789456)
        msg.add_string("q")
        msg.add_string("hello")
        msg.add_string("x" * 1000)
        self.assertEqual(msg.asbytes(), self.__a)

        msg = Message()
        msg.add_boolean(True)
        msg.add_boolean(False)
        msg.add_byte(byte_chr(0xF3))

        msg.add_bytes(zero_byte + byte_chr(0x3F))
        msg.add_list(["huey", "dewey", "louie"])
        self.assertEqual(msg.asbytes(), self.__b)

        msg = Message()
        msg.add_int64(5)
        msg.add_int64(0xF5E4D3C2B109)
        msg.add_mpint(17)
        msg.add_mpint(0xF5E4D3C2B109)
        msg.add_mpint(-0x65E4D3C2B109)
        self.assertEqual(msg.asbytes(), self.__c)

    def test_decode(self):
        msg = Message(self.__a)
        self.assertEqual(msg.get_int(), 23)
        self.assertEqual(msg.get_int(), 123789456)
        self.assertEqual(msg.get_text(), "q")
        self.assertEqual(msg.get_text(), "hello")
        self.assertEqual(msg.get_text(), "x" * 1000)

        msg = Message(self.__b)
        self.assertEqual(msg.get_boolean(), True)
        self.assertEqual(msg.get_boolean(), False)
        self.assertEqual(msg.get_byte(), byte_chr(0xF3))
        self.assertEqual(msg.get_bytes(2), zero_byte + byte_chr(0x3F))
        self.assertEqual(msg.get_list(), ["huey", "dewey", "louie"])

        msg = Message(self.__c)
        self.assertEqual(msg.get_int64(), 5)
        self.assertEqual(msg.get_int64(), 0xF5E4D3C2B109)
        self.assertEqual(msg.get_mpint(), 17)
        self.assertEqual(msg.get_mpint(), 0xF5E4D3C2B109)
        self.assertEqual(msg.get_mpint(), -0x65E4D3C2B109)

    def test_add(self):
        msg = Message()
        msg.add(5)
        msg.add(0x1122334455)
        msg.add(0xF00000000000000000)
        msg.add(True)
        msg.add("cat")
        msg.add(["a", "b"])
        self.assertEqual(msg.asbytes(), self.__d)

    def test_misc(self):
        msg = Message(self.__d)
        self.assertEqual(msg.get_adaptive_int(), 5)
        self.assertEqual(msg.get_adaptive_int(), 0x1122334455)
        self.assertEqual(msg.get_adaptive_int(), 0xF00000000000000000)
        self.assertEqual(msg.get_so_far(), self.__d[:29])
        self.assertEqual(msg.get_remainder(), self.__d[29:])
        msg.rewind()
        self.assertEqual(msg.get_adaptive_int(), 5)
        self.assertEqual(msg.get_so_far(), self.__d[:4])
        self.assertEqual(msg.get_remainder(), self.__d[4:])

    def test_bytes_str_and_repr(self):
        msg = Message(self.__d)
        assert str(msg) == f"paramiko.Message({self.__d!r})"
        assert repr(msg) == str(msg)
        assert bytes(msg) == msg.asbytes() == self.__d
