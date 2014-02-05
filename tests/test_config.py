# Copyright (C) 2013 Christopher Swenson <chris@caswenson.com>
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
Some unit tests for the config file parser.
"""

import paramiko
import unittest
from StringIO import StringIO


class ConfigTest (unittest.TestCase):
		def test_parse_dos_crlf_succeeds(self):
				config_file = StringIO("host abcqwerty\r\nHostName 127.0.0.1\r\n")
				config = paramiko.SSHConfig()
				config.parse(config_file)
				self.assertEqual(config.lookup("abcqwerty")["hostname"], "127.0.0.1")
