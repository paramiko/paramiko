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
Some unit tests for the ssh2 protocol in Transport.
"""

import unittest
from loop import LoopSocket
from Crypto.Cipher import AES
from Crypto.Hash import SHA, HMAC
from ssh import Message, Packetizer, util

class PacketizerTest (unittest.TestCase):

    def test_1_write (self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger('ssh.transport'))
        p.set_hexdump(True)
        cipher = AES.new('\x00' * 16, AES.MODE_CBC, '\x55' * 16)
        p.set_outbound_cipher(cipher, 16, SHA, 12, '\x1f' * 20)

        # message has to be at least 16 bytes long, so we'll have at least one
        # block of data encrypted that contains zero random padding bytes
        m = Message()
        m.add_byte(chr(100))
        m.add_int(100)
        m.add_int(1)
        m.add_int(900)
        p.send_message(m)
        data = rsock.recv(100)
        # 32 + 12 bytes of MAC = 44
        self.assertEquals(44, len(data))
        self.assertEquals('\x43\x91\x97\xbd\x5b\x50\xac\x25\x87\xc2\xc4\x6b\xc7\xe9\x38\xc0', data[:16])
    
    def test_2_read (self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger('ssh.transport'))
        p.set_hexdump(True)
        cipher = AES.new('\x00' * 16, AES.MODE_CBC, '\x55' * 16)
        p.set_inbound_cipher(cipher, 16, SHA, 12, '\x1f' * 20)
        
        wsock.send('C\x91\x97\xbd[P\xac%\x87\xc2\xc4k\xc7\xe98\xc0' + \
                   '\x90\xd2\x16V\rqsa8|L=\xfb\x97}\xe2n\x03\xb1\xa0\xc2\x1c\xd6AAL\xb4Y')
        cmd, m = p.read_message()
        self.assertEquals(100, cmd)
        self.assertEquals(100, m.get_int())
        self.assertEquals(1, m.get_int())
        self.assertEquals(900, m.get_int())
