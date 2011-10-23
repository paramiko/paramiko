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
Some unit tests for ssh protocol message blocks.
"""

import unittest
from ssh.message import Message


class MessageTest (unittest.TestCase):

    __a = '\x00\x00\x00\x17\x07\x60\xe0\x90\x00\x00\x00\x01q\x00\x00\x00\x05hello\x00\x00\x03\xe8' + ('x' * 1000)
    __b = '\x01\x00\xf3\x00\x3f\x00\x00\x00\x10huey,dewey,louie'
    __c = '\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\xf5\xe4\xd3\xc2\xb1\x09\x00\x00\x00\x01\x11\x00\x00\x00\x07\x00\xf5\xe4\xd3\xc2\xb1\x09\x00\x00\x00\x06\x9a\x1b\x2c\x3d\x4e\xf7'
    __d = '\x00\x00\x00\x05\x00\x00\x00\x05\x11\x22\x33\x44\x55\x01\x00\x00\x00\x03cat\x00\x00\x00\x03a,b'

    def test_1_encode(self):
        msg = Message()
        msg.add_int(23)
        msg.add_int(123789456)
        msg.add_string('q')
        msg.add_string('hello')
        msg.add_string('x' * 1000)
        self.assertEquals(str(msg), self.__a)

        msg = Message()
        msg.add_boolean(True)
        msg.add_boolean(False)
        msg.add_byte('\xf3')
        msg.add_bytes('\x00\x3f')
        msg.add_list(['huey', 'dewey', 'louie'])
        self.assertEquals(str(msg), self.__b)

        msg = Message()
        msg.add_int64(5)
        msg.add_int64(0xf5e4d3c2b109L)
        msg.add_mpint(17)
        msg.add_mpint(0xf5e4d3c2b109L)
        msg.add_mpint(-0x65e4d3c2b109L)
        self.assertEquals(str(msg), self.__c)

    def test_2_decode(self):
        msg = Message(self.__a)
        self.assertEquals(msg.get_int(), 23)
        self.assertEquals(msg.get_int(), 123789456)
        self.assertEquals(msg.get_string(), 'q')
        self.assertEquals(msg.get_string(), 'hello')
        self.assertEquals(msg.get_string(), 'x' * 1000)

        msg = Message(self.__b)
        self.assertEquals(msg.get_boolean(), True)
        self.assertEquals(msg.get_boolean(), False)
        self.assertEquals(msg.get_byte(), '\xf3')
        self.assertEquals(msg.get_bytes(2), '\x00\x3f')
        self.assertEquals(msg.get_list(), ['huey', 'dewey', 'louie'])

        msg = Message(self.__c)
        self.assertEquals(msg.get_int64(), 5)
        self.assertEquals(msg.get_int64(), 0xf5e4d3c2b109L)
        self.assertEquals(msg.get_mpint(), 17)
        self.assertEquals(msg.get_mpint(), 0xf5e4d3c2b109L)
        self.assertEquals(msg.get_mpint(), -0x65e4d3c2b109L)

    def test_3_add(self):
        msg = Message()
        msg.add(5)
        msg.add(0x1122334455L)
        msg.add(True)
        msg.add('cat')
        msg.add(['a', 'b'])
        self.assertEquals(str(msg), self.__d)

    def test_4_misc(self):
        msg = Message(self.__d)
        self.assertEquals(msg.get_int(), 5)
        self.assertEquals(msg.get_mpint(), 0x1122334455L)
        self.assertEquals(msg.get_so_far(), self.__d[:13])
        self.assertEquals(msg.get_remainder(), self.__d[13:])
        msg.rewind()
        self.assertEquals(msg.get_int(), 5)
        self.assertEquals(msg.get_so_far(), self.__d[:4])
        self.assertEquals(msg.get_remainder(), self.__d[4:])

