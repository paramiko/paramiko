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
Some unit tests for the BufferedFile abstraction.
"""

import unittest
from paramiko.file import BufferedFile
from paramiko.common import linefeed_byte, crlf, cr_byte
import sys


class LoopbackFile (BufferedFile):
    """
    BufferedFile object that you can write data into, and then read it back.
    """
    def __init__(self, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self._set_mode(mode, bufsize)
        self.buffer = bytes()

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
            f.write(b'hi')
            self.assertTrue(False, 'no exception on write to read-only file')
        except:
            pass
        f.close()

        f = LoopbackFile('w')
        try:
            f.read(1)
            self.assertTrue(False, 'no exception to read from write-only file')
        except:
            pass
        f.close()

    def test_2_readline(self):
        f = LoopbackFile('r+U')
        f.write(b'First line.\nSecond line.\r\nThird line.\n' + 
                b'Fourth line.\nFinal line non-terminated.')
        
        self.assertEqual(f.readline(), 'First line.\n')
        # universal newline mode should convert this linefeed:
        self.assertEqual(f.readline(), 'Second line.\n')
        # truncated line:
        self.assertEqual(f.readline(7), 'Third l')
        self.assertEqual(f.readline(), 'ine.\n')
        # newline should be detected and only the fourth line returned
        self.assertEqual(f.readline(39), 'Fourth line.\n')
        self.assertEqual(f.readline(), 'Final line non-terminated.')
        self.assertEqual(f.readline(), '')
        f.close()
        try:
            f.readline()
            self.assertTrue(False, 'no exception on readline of closed file')
        except IOError:
            pass
        self.assertTrue(linefeed_byte in f.newlines)
        self.assertTrue(crlf in f.newlines)
        self.assertTrue(cr_byte not in f.newlines)

    def test_3_lf(self):
        """
        try to trick the linefeed detector.
        """
        f = LoopbackFile('r+U')
        f.write(b'First line.\r')
        self.assertEqual(f.readline(), 'First line.\n')
        f.write(b'\nSecond.\r\n')
        self.assertEqual(f.readline(), 'Second.\n')
        f.close()
        self.assertEqual(f.newlines, crlf)

    def test_4_write(self):
        """
        verify that write buffering is on.
        """
        f = LoopbackFile('r+', 1)
        f.write(b'Complete line.\nIncomplete line.')
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
        self.assertEqual(f.read(1), b'')
        f.flush()
        self.assertEqual(f.read(5), b'Not\nq')
        self.assertEqual(f.read(10), b'uite\n512 b')
        self.assertEqual(f.read(9), b'ytes.\n')
        self.assertEqual(f.read(3), b'')
        f.close()

    def test_6_buffering(self):
        """
        verify that flushing happens automatically on buffer crossing.
        """
        f = LoopbackFile('r+', 16)
        f.write(b'Too small.')
        self.assertEqual(f.read(4), b'')
        f.write(b'  ')
        self.assertEqual(f.read(4), b'')
        f.write(b'Enough.')
        self.assertEqual(f.read(20), b'Too small.  Enough.')
        f.close()

    def test_7_read_all(self):
        """
        verify that read(-1) returns everything left in the file.
        """
        f = LoopbackFile('r+', 16)
        f.write(b'The first thing you need to do is open your eyes. ')
        f.write(b'Then, you need to close them again.\n')
        s = f.read(-1)
        self.assertEqual(s, b'The first thing you need to do is open your eyes. Then, you ' +
                            b'need to close them again.\n')
        f.close()

    def test_8_buffering(self):
        """
        verify that buffered objects can be written
        """
        if sys.version_info[0] == 2:
            f = LoopbackFile('r+', 16)
            f.write(buffer(b'Too small.'))
            f.close()

if __name__ == '__main__':
    from unittest import main
    main()

