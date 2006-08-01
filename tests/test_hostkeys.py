# Copyright (C) 2006 Robey Pointer <robey@lag.net>
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
Some unit tests for HostKeys.
"""

import base64
from binascii import hexlify
import os
import unittest
import paramiko


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
"""

keyblob = """\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest (unittest.TestCase):

    def setUp(self):
        f = open('hostfile.temp', 'w')
        f.write(test_hosts_file)
        f.close()

    def tearDown(self):
        os.unlink('hostfile.temp')

    def test_1_load(self):
        hostdict = paramiko.HostKeys('hostfile.temp')
        self.assertEquals(2, len(hostdict))
        self.assertEquals(1, len(hostdict.values()[0]))
        self.assertEquals(1, len(hostdict.values()[1]))
        fp = hexlify(hostdict['secure.example.com']['ssh-rsa'].get_fingerprint()).upper()
        self.assertEquals('E6684DB30E109B67B70FF1DC5C7F1363', fp)

    def test_2_add(self):
        hostdict = paramiko.HostKeys('hostfile.temp')
        hh = '|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c='
        key = paramiko.RSAKey(data=base64.decodestring(keyblob))
        hostdict.add(hh, 'ssh-rsa', key)
        self.assertEquals(3, len(hostdict))
        x = hostdict['foo.example.com']
        fp = hexlify(x['ssh-rsa'].get_fingerprint()).upper()
        self.assertEquals('7EC91BB336CB6D810B124B1353C32396', fp)
        self.assert_(hostdict.check('foo.example.com', key))

    def test_3_dict(self):
        hostdict = paramiko.HostKeys('hostfile.temp')
        self.assert_('secure.example.com' in hostdict)
        self.assert_('not.example.com' not in hostdict)
        self.assert_(hostdict.has_key('secure.example.com'))
        self.assert_(not hostdict.has_key('not.example.com'))
        x = hostdict.get('secure.example.com', None)
        self.assert_(x is not None)
        fp = hexlify(x['ssh-rsa'].get_fingerprint()).upper()
        self.assertEquals('E6684DB30E109B67B70FF1DC5C7F1363', fp)
        i = 0
        for key in hostdict:
            i += 1
        self.assertEquals(2, i)
        
