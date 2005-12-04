#!/usr/bin/python

# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
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
Some unit tests for utility functions.
"""

import cStringIO
import unittest
from Crypto.Hash import SHA
import paramiko.util


test_config_file = """\
Host *
    User robey
    IdentityFile    =~/.ssh/id_rsa

# comment
Host *.example.com
    \tUser bjork
Port=3333
Host *
 \t  \t Crazy something dumb  
Host spoo.example.com
Crazy something else
"""


class UtilTest (unittest.TestCase):

    K = 14730343317708716439807310032871972459448364195094179797249681733965528989482751523943515690110179031004049109375612685505881911274101441415545039654102474376472240501616988799699744135291070488314748284283496055223852115360852283821334858541043710301057312858051901453919067023103730011648890038847384890504L

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_1_parse_config(self):
        global test_config_file
        f = cStringIO.StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        self.assertEquals(config, [ {'identityfile': '~/.ssh/id_rsa', 'host': '*', 'user': 'robey',
                                     'crazy': 'something dumb  '},
                                    {'host': '*.example.com', 'user': 'bjork', 'port': '3333'},
                                    {'host': 'spoo.example.com', 'crazy': 'something else'}])

    def test_2_host_config(self):
        global test_config_file
        f = cStringIO.StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        c = paramiko.util.lookup_ssh_host_config('irc.danger.com', config)
        self.assertEquals(c, {'identityfile': '~/.ssh/id_rsa', 'user': 'robey', 'crazy': 'something dumb  '})
        c = paramiko.util.lookup_ssh_host_config('irc.example.com', config)
        self.assertEquals(c, {'identityfile': '~/.ssh/id_rsa', 'user': 'bjork', 'crazy': 'something dumb  ', 'port': '3333'})
        c = paramiko.util.lookup_ssh_host_config('spoo.example.com', config)
        self.assertEquals(c, {'identityfile': '~/.ssh/id_rsa', 'user': 'bjork', 'crazy': 'something else', 'port': '3333'})

    def test_3_generate_key_bytes(self):
        x = paramiko.util.generate_key_bytes(SHA, 'ABCDEFGH', 'This is my secret passphrase.', 64)
        hex = ''.join(['%02x' % ord(c) for c in x])
        self.assertEquals(hex, '9110e2f6793b69363e58173e9436b13a5a4b339005741d5c680e505f57d871347b4239f14fb5c46e857d5e100424873ba849ac699cea98d729e57b3e84378e8b')
