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
Some unit tests for HostKeys.
"""

import base64
from binascii import hexlify
import os
import unittest
import ssh


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

keyblob_dss = """\
AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug6s6fgwj/oLjYbVtjAy6pl/\
h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65X1FyDkg6g8tvCnaNB8Xp/UUhuzHuGsMIipRxBxw9LF60\
8EqZcj1E3ytktoW5B5OcjrkEoz3xG7C+rpIjYvAAAAFQDwz4UnmsGiSNu5iqjn3uTzwUpshwAAAIE\
AkxfFeY8P2wZpDjX0MimZl5wkoFQDL25cPzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+\
Ngw3qIch/WgRmMHy4kBq1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ejg\
4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV1BVYd0lYukmnjO\
1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9kUgyB7+NwacIBlXa8cMDL7Q/69o\
0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwjQgE="""


class HostKeysTest (unittest.TestCase):

    def setUp(self):
        f = open('hostfile.temp', 'w')
        f.write(test_hosts_file)
        f.close()

    def tearDown(self):
        os.unlink('hostfile.temp')

    def test_1_load(self):
        hostdict = ssh.HostKeys('hostfile.temp')
        self.assertEquals(2, len(hostdict))
        self.assertEquals(1, len(hostdict.values()[0]))
        self.assertEquals(1, len(hostdict.values()[1]))
        fp = hexlify(hostdict['secure.example.com']['ssh-rsa'].get_fingerprint()).upper()
        self.assertEquals('E6684DB30E109B67B70FF1DC5C7F1363', fp)

    def test_2_add(self):
        hostdict = ssh.HostKeys('hostfile.temp')
        hh = '|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c='
        key = ssh.RSAKey(data=base64.decodestring(keyblob))
        hostdict.add(hh, 'ssh-rsa', key)
        self.assertEquals(3, len(hostdict))
        x = hostdict['foo.example.com']
        fp = hexlify(x['ssh-rsa'].get_fingerprint()).upper()
        self.assertEquals('7EC91BB336CB6D810B124B1353C32396', fp)
        self.assert_(hostdict.check('foo.example.com', key))

    def test_3_dict(self):
        hostdict = ssh.HostKeys('hostfile.temp')
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
        
    def test_4_dict_set(self):
        hostdict = ssh.HostKeys('hostfile.temp')
        key = ssh.RSAKey(data=base64.decodestring(keyblob))
        key_dss = ssh.DSSKey(data=base64.decodestring(keyblob_dss))
        hostdict['secure.example.com'] = {
            'ssh-rsa': key,
            'ssh-dss': key_dss
        }
        hostdict['fake.example.com'] = {}
        hostdict['fake.example.com']['ssh-rsa'] = key
        
        self.assertEquals(3, len(hostdict))
        self.assertEquals(2, len(hostdict.values()[0]))
        self.assertEquals(1, len(hostdict.values()[1]))
        self.assertEquals(1, len(hostdict.values()[2]))
        fp = hexlify(hostdict['secure.example.com']['ssh-rsa'].get_fingerprint()).upper()
        self.assertEquals('7EC91BB336CB6D810B124B1353C32396', fp)
        fp = hexlify(hostdict['secure.example.com']['ssh-dss'].get_fingerprint()).upper()
        self.assertEquals('4478F0B9A23CC5182009FF755BC1D26C', fp)
