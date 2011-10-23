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
Some unit tests for the BufferedFile abstraction.
"""

import unittest
from ssh.file import BufferedFile


class LoopbackFile (BufferedFile):
    """
    BufferedFile object that you can write data into, and then read it back.
    """
    def __init__(self, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self._set_mode(mode, bufsize)
        self.buffer = ''

    def _read(self, size):
        if len(self.buffer) == 0:
            return None
        if size > len(self.buffer):
            size = len(self.buffer)
        data = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return data

    def _write(self, data):
        self.buffer += data
        return len(data)


class BufferedFileTest (unittest.TestCase):

    def test_1_simple(self):
        f = LoopbackFile('r')
        try:
            f.write('hi')
            self.assert_(False, 'no exception on write to read-only file')
        except:
            pass
        f.close()

        f = LoopbackFile('w')
        try:
            f.read(1)
            self.assert_(False, 'no exception to read from write-only file')
        except:
            pass
        f.close()

    def test_2_readline(self):
        f = LoopbackFile('r+U')
        f.write('First line.\nSecond line.\r\nThird line.\nFinal line non-terminated.')
        self.assertEqual(f.readline(), 'First line.\n')
        # universal newline mode should convert this linefeed:
        self.assertEqual(f.readline(), 'Second line.\n')
        # truncated line:
        self.assertEqual(f.readline(7), 'Third l')
        self.assertEqual(f.readline(), 'ine.\n')
        self.assertEqual(f.readline(), 'Final line non-terminated.')
        self.assertEqual(f.readline(), '')
        f.close()
        try:
            f.readline()
            self.assert_(False, 'no exception on readline of closed file')
        except IOError:
            pass
        self.assert_('\n' in f.newlines)
        self.assert_('\r\n' in f.newlines)
        self.assert_('\r' not in f.newlines)

    def test_3_lf(self):
        """
        try to trick the linefeed detector.
        """
        f = LoopbackFile('r+U')
        f.write('First line.\r')
        self.assertEqual(f.readline(), 'First line.\n')
        f.write('\nSecond.\r\n')
        self.assertEqual(f.readline(), 'Second.\n')
        f.close()
        self.assertEqual(f.newlines, '\r\n')

    def test_4_write(self):
        """
        verify that write buffering is on.
        """
        f = LoopbackFile('r+', 1)
        f.write('Complete line.\nIncomplete line.')
        self.assertEqual(f.readline(), 'Complete line.\n')
        self.assertEqual(f.readline(), '')
        f.write('..\n')
        self.assertEqual(f.readline(), 'Incomplete line...\n')
        f.close()

    def test_5_flush(self):
        """
        verify that flush will force a write.
        """
        f = LoopbackFile('r+', 512)
        f.write('Not\nquite\n512 bytes.\n')
        self.assertEqual(f.read(1), '')
        f.flush()
        self.assertEqual(f.read(5), 'Not\nq')
        self.assertEqual(f.read(10), 'uite\n512 b')
        self.assertEqual(f.read(9), 'ytes.\n')
        self.assertEqual(f.read(3), '')
        f.close()

    def test_6_buffering(self):
        """
        verify that flushing happens automatically on buffer crossing.
        """
        f = LoopbackFile('r+', 16)
        f.write('Too small.')
        self.assertEqual(f.read(4), '')
        f.write('  ')
        self.assertEqual(f.read(4), '')
        f.write('Enough.')
        self.assertEqual(f.read(20), 'Too small.  Enough.')
        f.close()

    def test_7_read_all(self):
        """
        verify that read(-1) returns everything left in the file.
        """
        f = LoopbackFile('r+', 16)
        f.write('The first thing you need to do is open your eyes. ')
        f.write('Then, you need to close them again.\n')
        s = f.read(-1)
        self.assertEqual(s, 'The first thing you need to do is open your eyes. Then, you ' +
                         'need to close them again.\n')
        f.close()
