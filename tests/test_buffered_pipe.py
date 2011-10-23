# Copyright (C) 2006-2007  Jeff Forcier <jeff@bitprophet.org>
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
Some unit tests for BufferedPipe.
"""

import threading
import time
import unittest
from ssh.buffered_pipe import BufferedPipe, PipeTimeout
from ssh import pipe


def delay_thread(pipe):
    pipe.feed('a')
    time.sleep(0.5)
    pipe.feed('b')
    pipe.close()


def close_thread(pipe):
    time.sleep(0.2)
    pipe.close()


class BufferedPipeTest (unittest.TestCase):

    assertTrue = unittest.TestCase.failUnless   # for Python 2.3 and below
    assertFalse = unittest.TestCase.failIf      # for Python 2.3 and below

    def test_1_buffered_pipe(self):
        p = BufferedPipe()
        self.assert_(not p.read_ready())
        p.feed('hello.')
        self.assert_(p.read_ready())
        data = p.read(6)
        self.assertEquals('hello.', data)
        
        p.feed('plus/minus')
        self.assertEquals('plu', p.read(3))
        self.assertEquals('s/m', p.read(3))
        self.assertEquals('inus', p.read(4))
        
        p.close()
        self.assert_(not p.read_ready())
        self.assertEquals('', p.read(1))

    def test_2_delay(self):
        p = BufferedPipe()
        self.assert_(not p.read_ready())
        threading.Thread(target=delay_thread, args=(p,)).start()
        self.assertEquals('a', p.read(1, 0.1))
        try:
            p.read(1, 0.1)
            self.assert_(False)
        except PipeTimeout:
            pass
        self.assertEquals('b', p.read(1, 1.0))
        self.assertEquals('', p.read(1))

    def test_3_close_while_reading(self):
        p = BufferedPipe()
        threading.Thread(target=close_thread, args=(p,)).start()
        data = p.read(1, 1.0)
        self.assertEquals('', data)

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

