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
Some unit tests for public/private key objects.
"""

import unittest
from paramiko import RSAKey, DSSKey, Message, util, randpool

# from openssh's ssh-keygen
PUB_RSA = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4c='
PUB_DSS = 'ssh-dss AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug6s6fgwj/oLjYbVtjAy6pl/h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65X1FyDkg6g8tvCnaNB8Xp/UUhuzHuGsMIipRxBxw9LF608EqZcj1E3ytktoW5B5OcjrkEoz3xG7C+rpIjYvAAAAFQDwz4UnmsGiSNu5iqjn3uTzwUpshwAAAIEAkxfFeY8P2wZpDjX0MimZl5wkoFQDL25cPzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgRmMHy4kBq1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ejg4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV1BVYd0lYukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9kUgyB7+NwacIBlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwjQgE='
FINGER_RSA = '1024 60:73:38:44:cb:51:86:65:7f:de:da:a2:2b:5a:57:d5'
FINGER_DSS = '1024 44:78:f0:b9:a2:3c:c5:18:20:09:ff:75:5b:c1:d2:6c'
SIGNED_RSA = '20:d7:8a:31:21:cb:f7:92:12:f2:a4:89:37:f5:78:af:e6:16:b6:25:b9:97:3d:a2:cd:5f:ca:20:21:73:4c:ad:34:73:8f:20:77:28:e2:94:15:08:d8:91:40:7a:85:83:bf:18:37:95:dc:54:1a:9b:88:29:6c:73:ca:38:b4:04:f1:56:b9:f2:42:9d:52:1b:29:29:b4:4f:fd:c9:2d:af:47:d2:40:76:30:f3:63:45:0c:d9:1d:43:86:0f:1c:70:e2:93:12:34:f3:ac:c5:0a:2f:14:50:66:59:f1:88:ee:c1:4a:e9:d1:9c:4e:46:f0:0e:47:6f:38:74:f1:44:a8'


class KeyTest (unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_1_generate_key_bytes(self):
        from Crypto.Hash import MD5
        key = util.generate_key_bytes(MD5, '\x01\x02\x03\x04', 'happy birthday', 30)
        exp = util.unhexify('61E1F272F4C1C4561586BD322498C0E924672780F47BB37DDA7D54019E64')
        self.assertEquals(exp, key)

    def test_2_load_rsa(self):
        key = RSAKey.from_private_key_file('tests/test_rsa.key')
        self.assertEquals('ssh-rsa', key.get_name())
        exp_rsa = FINGER_RSA.split()[1].replace(':', '')
        my_rsa = util.hexify(key.get_fingerprint()).lower()
        self.assertEquals(exp_rsa, my_rsa)
        self.assertEquals(PUB_RSA.split()[1], key.get_base64())
        self.assertEquals(1024, key.get_bits())

    def test_3_load_rsa_password(self):
        key = RSAKey.from_private_key_file('tests/test_rsa_password.key', 'television')
        self.assertEquals('ssh-rsa', key.get_name())
        exp_rsa = FINGER_RSA.split()[1].replace(':', '')
        my_rsa = util.hexify(key.get_fingerprint()).lower()
        self.assertEquals(exp_rsa, my_rsa)
        self.assertEquals(PUB_RSA.split()[1], key.get_base64())
        self.assertEquals(1024, key.get_bits())
        
    def test_4_load_dss(self):
        key = DSSKey.from_private_key_file('tests/test_dss.key')
        self.assertEquals('ssh-dss', key.get_name())
        exp_dss = FINGER_DSS.split()[1].replace(':', '')
        my_dss = util.hexify(key.get_fingerprint()).lower()
        self.assertEquals(exp_dss, my_dss)
        self.assertEquals(PUB_DSS.split()[1], key.get_base64())
        self.assertEquals(1024, key.get_bits())

    def test_5_load_dss_password(self):
        key = DSSKey.from_private_key_file('tests/test_dss_password.key', 'television')
        self.assertEquals('ssh-dss', key.get_name())
        exp_dss = FINGER_DSS.split()[1].replace(':', '')
        my_dss = util.hexify(key.get_fingerprint()).lower()
        self.assertEquals(exp_dss, my_dss)
        self.assertEquals(PUB_DSS.split()[1], key.get_base64())
        self.assertEquals(1024, key.get_bits())

    def test_6_compare_rsa(self):
        # verify that the private & public keys compare equal
        key = RSAKey.from_private_key_file('tests/test_rsa.key')
        self.assertEquals(key, key)
        pub = RSAKey(data=str(key))
        self.assert_(key.can_sign())
        self.assert_(not pub.can_sign())
        self.assertEquals(key, pub)

    def test_7_compare_dss(self):
        # verify that the private & public keys compare equal
        key = DSSKey.from_private_key_file('tests/test_dss.key')
        self.assertEquals(key, key)
        pub = DSSKey(data=str(key))
        self.assert_(key.can_sign())
        self.assert_(not pub.can_sign())
        self.assertEquals(key, pub)

    def test_8_sign_rsa(self):
        # verify that the rsa private key can sign and verify
        key = RSAKey.from_private_key_file('tests/test_rsa.key')
        msg = key.sign_ssh_data(randpool, 'ice weasels')
        self.assert_(type(msg) is Message)
        self.assertEquals('ssh-rsa', msg.get_string())
        sig = ''.join([chr(int(x, 16)) for x in SIGNED_RSA.split(':')])
        self.assertEquals(sig, msg.get_string())
        msg.rewind()
        pub = RSAKey(data=str(key))
        self.assert_(pub.verify_ssh_sig('ice weasels', msg))

    def test_9_sign_dss(self):
        # verify that the dss private key can sign and verify
        key = DSSKey.from_private_key_file('tests/test_dss.key')
        msg = key.sign_ssh_data(randpool, 'ice weasels')
        self.assert_(type(msg) is Message)
        self.assertEquals('ssh-dss', msg.get_string())
        # can't do the same test as we do for RSA, because DSS signatures
        # are usually different each time.  but we can test verification
        # anyway so it's ok.
        self.assertEquals(40, len(msg.get_string()))
        msg.rewind()
        pub = DSSKey(data=str(key))
        self.assert_(pub.verify_ssh_sig('ice weasels', msg))
    
    def test_A_generate_rsa(self):
        key = RSAKey.generate(1024)
        msg = key.sign_ssh_data(randpool, 'jerri blank')
        self.assert_(key.verify_ssh_sig('jerri blank', msg))

    def test_B_generate_dss(self):
        key = DSSKey.generate(1024)
        msg = key.sign_ssh_data(randpool, 'jerri blank')
        self.assert_(key.verify_ssh_sig('jerri blank', msg))
