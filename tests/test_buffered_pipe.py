# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
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
Some unit tests for BufferedPipe.
"""

import threading
import time
import unittest

from paramiko.buffered_pipe import BufferedPipe, PipeTimeout
from paramiko import pipe
from paramiko.py3compat import b


def delay_thread(p):
    p.feed("a")
    time.sleep(0.5)
    p.feed("b")
    p.close()


def close_thread(p):
    time.sleep(0.2)
    p.close()


class BufferedPipeTest(unittest.TestCase):
    def test_1_buffered_pipe(self):
        p = BufferedPipe()
        self.assertTrue(not p.read_ready())
        p.feed("hello.")
        self.assertTrue(p.read_ready())
        data = p.read(6)
        self.assertEqual(b"hello.", data)

        p.feed("plus/minus")
        self.assertEqual(b"plu", p.read(3))
        self.assertEqual(b"s/m", p.read(3))
        self.assertEqual(b"inus", p.read(4))

        p.close()
        self.assertTrue(not p.read_ready())
        self.assertEqual(b"", p.read(1))

    def test_2_delay(self):
        p = BufferedPipe()
        self.assertTrue(not p.read_ready())
        threading.Thread(target=delay_thread, args=(p,)).start()
        self.assertEqual(b"a", p.read(1, 0.1))
        try:
            p.read(1, 0.1)
            self.assertTrue(False)
        except PipeTimeout:
            pass
        self.assertEqual(b"b", p.read(1, 1.0))
        self.assertEqual(b"", p.read(1))

    def test_3_close_while_reading(self):
        p = BufferedPipe()
        threading.Thread(target=close_thread, args=(p,)).start()
        data = p.read(1, 1.0)
        self.assertEqual(b"", data)

    def test_4_or_pipe(self):
        p = pipe.make_pipe()
        p1, p2 = pipe.make_or_pipe(p)
        self.assertFalse(p._set)
        p1.set()
        self.assertTrue(p._set)
        p2.set()
        self.assertTrue(p._set)
        p1.clear()
        self.assertTrue(p._set)
        p2.clear()
        self.assertFalse(p._set)
