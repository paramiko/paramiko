#!/usr/bin/python

# Copyright (C) 2003-2004 Robey Pointer <robey@lag.net>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
do the unit tests!
"""

import sys, os, unittest
sys.path.append('tests/')

from test_file import BufferedFileTest
from test_sftp import SFTPTest

suite = unittest.TestSuite()
suite.addTest(unittest.makeSuite(BufferedFileTest))
suite.addTest(unittest.makeSuite(SFTPTest))
unittest.TextTestRunner(verbosity=2).run(suite)

