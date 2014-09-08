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
Some unit tests for public/private key objects.
"""

import unittest
import os
from binascii import hexlify
from hashlib import md5

from paramiko import RSAKey, DSSKey, ECDSAKey, Message, util
from paramiko.py3compat import StringIO, byte_chr, b, bytes

from tests.util import test_path

# from openssh's ssh-keygen
PUB_RSA = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4c='
PUB_DSS = 'ssh-dss AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug6s6fgwj/oLjYbVtjAy6pl/h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65X1FyDkg6g8tvCnaNB8Xp/UUhuzHuGsMIipRxBxw9LF608EqZcj1E3ytktoW5B5OcjrkEoz3xG7C+rpIjYvAAAAFQDwz4UnmsGiSNu5iqjn3uTzwUpshwAAAIEAkxfFeY8P2wZpDjX0MimZl5wkoFQDL25cPzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgRmMHy4kBq1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ejg4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV1BVYd0lYukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9kUgyB7+NwacIBlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwjQgE='
PUB_ECDSA = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJSPZm3ZWkvk/Zx8WP+fZRZ5/NBBHnGQwR6uIC6XHGPDIHuWUzIjAwA0bzqkOUffEsbLe+uQgKl5kbc/L8KA/eo='

FINGER_RSA = '1024 60:73:38:44:cb:51:86:65:7f:de:da:a2:2b:5a:57:d5'
FINGER_DSS = '1024 44:78:f0:b9:a2:3c:c5:18:20:09:ff:75:5b:c1:d2:6c'
FINGER_ECDSA = '256 25:19:eb:55:e6:a1:47:ff:4f:38:d2:75:6f:a5:d5:60'
SIGNED_RSA = '20:d7:8a:31:21:cb:f7:92:12:f2:a4:89:37:f5:78:af:e6:16:b6:25:b9:97:3d:a2:cd:5f:ca:20:21:73:4c:ad:34:73:8f:20:77:28:e2:94:15:08:d8:91:40:7a:85:83:bf:18:37:95:dc:54:1a:9b:88:29:6c:73:ca:38:b4:04:f1:56:b9:f2:42:9d:52:1b:29:29:b4:4f:fd:c9:2d:af:47:d2:40:76:30:f3:63:45:0c:d9:1d:43:86:0f:1c:70:e2:93:12:34:f3:ac:c5:0a:2f:14:50:66:59:f1:88:ee:c1:4a:e9:d1:9c:4e:46:f0:0e:47:6f:38:74:f1:44:a8'

RSA_PRIVATE_OUT = """\
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKCAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAM
s6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZ
v3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4cCASMC
ggCAEiI6plhqipt4P05L3PYr0pHZq2VPEbE4k9eI/gRKo/c1VJxY3DJnc1cenKsk
trQRtW3OxCEufqsX5PNec6VyKkW+Ox6beJjMKm4KF8ZDpKi9Nw6MdX3P6Gele9D9
+ieyhVFljrnAqcXsgChTBOYlL2imqCs3qRGAJ3cMBIAx3VsCQQD3pIFVYW398kE0
n0e1icEpkbDRV4c5iZVhu8xKy2yyfy6f6lClSb2+Ub9uns7F3+b5v0pYSHbE9+/r
OpRq83AfAkEA2rMZlr8SnMXgnyka2LuggA9QgMYy18hyao1dUxySubNDa9N+q2QR
mwDisTUgRFHKIlDHoQmzPbXAmYZX1YlDmQJBAPCRLS5epV0XOAc7pL762OaNhzHC
veAfQKgVhKBt105PqaKpGyQ5AXcNlWQlPeTK4GBTbMrKDPna6RBkyrEJvV8CQBK+
5O+p+kfztCrmRCE0p1tvBuZ3Y3GU1ptrM+KNa6mEZN1bRV8l1Z+SXJLYqv6Kquz/
nBUeFq2Em3rfoSDugiMCQDyG3cxD5dKX3IgkhLyBWls/FLDk4x/DQ+NUTu0F1Cu6
JJye+5ARLkL0EweMXf0tmIYfWItDLsWB0fKg/56h0js=
-----END RSA PRIVATE KEY-----
"""

DSS_PRIVATE_OUT = """\
-----BEGIN DSA PRIVATE KEY-----
MIIBvgIBAAKCAIEA54GmA2d9HOv+3CYBBG7ZfBYCncIW2tWe6Dqzp+DCP+guNhtW
2MDLqmX+HQQoJbHat/Uh63I2xPFaueID0jod4OPrlfUXIOSDqDy28Kdo0Hxen9RS
G7Me4awwiKlHEHHD0sXrTwSplyPUTfK2S2hbkHk5yOuQSjPfEbsL6ukiNi8CFQDw
z4UnmsGiSNu5iqjn3uTzwUpshwKCAIEAkxfFeY8P2wZpDjX0MimZl5wkoFQDL25c
PzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgRmMHy4kBq
1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ejg4Ok10+X
FDxlqZo8Y+wCggCARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV1BVYd0lY
ukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9kUgyB7+N
wacIBlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwjQgECFGI9
QPSch9pT9XHqn+1rZ4bK+QGA
-----END DSA PRIVATE KEY-----
"""

ECDSA_PRIVATE_OUT = """\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKB6ty3yVyKEnfF/zprx0qwC76MsMlHY4HXCnqho2eKioAoGCCqGSM49
AwEHoUQDQgAElI9mbdlaS+T9nHxY/59lFnn80EEecZDBHq4gLpccY8Mge5ZTMiMD
ADRvOqQ5R98Sxst765CAqXmRtz8vwoD96g==
-----END EC PRIVATE KEY-----
"""

x1234 = b'\x01\x02\x03\x04'


class KeyTest (unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_1_generate_key_bytes(self):
        key = util.generate_key_bytes(md5, x1234, 'happy birthday', 30)
        exp = b'\x61\xE1\xF2\x72\xF4\xC1\xC4\x56\x15\x86\xBD\x32\x24\x98\xC0\xE9\x24\x67\x27\x80\xF4\x7B\xB3\x7D\xDA\x7D\x54\x01\x9E\x64'
        self.assertEqual(exp, key)

    def test_2_load_rsa(self):
        key = RSAKey.from_private_key_file(test_path('test_rsa.key'))
        self.assertEqual('ssh-rsa', key.get_name())
        exp_rsa = b(FINGER_RSA.split()[1].replace(':', ''))
        my_rsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_rsa, my_rsa)
        self.assertEqual(PUB_RSA.split()[1], key.get_base64())
        self.assertEqual(1024, key.get_bits())

        s = StringIO()
        key.write_private_key(s)
        self.assertEqual(RSA_PRIVATE_OUT, s.getvalue())
        s.seek(0)
        key2 = RSAKey.from_private_key(s)
        self.assertEqual(key, key2)

    def test_3_load_rsa_password(self):
        key = RSAKey.from_private_key_file(test_path('test_rsa_password.key'), 'television')
        self.assertEqual('ssh-rsa', key.get_name())
        exp_rsa = b(FINGER_RSA.split()[1].replace(':', ''))
        my_rsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_rsa, my_rsa)
        self.assertEqual(PUB_RSA.split()[1], key.get_base64())
        self.assertEqual(1024, key.get_bits())
        
    def test_4_load_dss(self):
        key = DSSKey.from_private_key_file(test_path('test_dss.key'))
        self.assertEqual('ssh-dss', key.get_name())
        exp_dss = b(FINGER_DSS.split()[1].replace(':', ''))
        my_dss = hexlify(key.get_fingerprint())
        self.assertEqual(exp_dss, my_dss)
        self.assertEqual(PUB_DSS.split()[1], key.get_base64())
        self.assertEqual(1024, key.get_bits())

        s = StringIO()
        key.write_private_key(s)
        self.assertEqual(DSS_PRIVATE_OUT, s.getvalue())
        s.seek(0)
        key2 = DSSKey.from_private_key(s)
        self.assertEqual(key, key2)

    def test_5_load_dss_password(self):
        key = DSSKey.from_private_key_file(test_path('test_dss_password.key'), 'television')
        self.assertEqual('ssh-dss', key.get_name())
        exp_dss = b(FINGER_DSS.split()[1].replace(':', ''))
        my_dss = hexlify(key.get_fingerprint())
        self.assertEqual(exp_dss, my_dss)
        self.assertEqual(PUB_DSS.split()[1], key.get_base64())
        self.assertEqual(1024, key.get_bits())

    def test_6_compare_rsa(self):
        # verify that the private & public keys compare equal
        key = RSAKey.from_private_key_file(test_path('test_rsa.key'))
        self.assertEqual(key, key)
        pub = RSAKey(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_7_compare_dss(self):
        # verify that the private & public keys compare equal
        key = DSSKey.from_private_key_file(test_path('test_dss.key'))
        self.assertEqual(key, key)
        pub = DSSKey(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_8_sign_rsa(self):
        # verify that the rsa private key can sign and verify
        key = RSAKey.from_private_key_file(test_path('test_rsa.key'))
        msg = key.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ssh-rsa', msg.get_text())
        sig = bytes().join([byte_chr(int(x, 16)) for x in SIGNED_RSA.split(':')])
        self.assertEqual(sig, msg.get_binary())
        msg.rewind()
        pub = RSAKey(data=key.asbytes())
        self.assertTrue(pub.verify_ssh_sig(b'ice weasels', msg))

    def test_9_sign_dss(self):
        # verify that the dss private key can sign and verify
        key = DSSKey.from_private_key_file(test_path('test_dss.key'))
        msg = key.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ssh-dss', msg.get_text())
        # can't do the same test as we do for RSA, because DSS signatures
        # are usually different each time.  but we can test verification
        # anyway so it's ok.
        self.assertEqual(40, len(msg.get_binary()))
        msg.rewind()
        pub = DSSKey(data=key.asbytes())
        self.assertTrue(pub.verify_ssh_sig(b'ice weasels', msg))

    def test_A_generate_rsa(self):
        key = RSAKey.generate(1024)
        msg = key.sign_ssh_data(b'jerri blank')
        msg.rewind()
        self.assertTrue(key.verify_ssh_sig(b'jerri blank', msg))

    def test_B_generate_dss(self):
        key = DSSKey.generate(1024)
        msg = key.sign_ssh_data(b'jerri blank')
        msg.rewind()
        self.assertTrue(key.verify_ssh_sig(b'jerri blank', msg))

    def test_10_load_ecdsa(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa.key'))
        self.assertEqual('ecdsa-sha2-nistp256', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA.split()[1], key.get_base64())
        self.assertEqual(256, key.get_bits())

        s = StringIO()
        key.write_private_key(s)
        self.assertEqual(ECDSA_PRIVATE_OUT, s.getvalue())
        s.seek(0)
        key2 = ECDSAKey.from_private_key(s)
        self.assertEqual(key, key2)

    def test_11_load_ecdsa_password(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_password.key'), b'television')
        self.assertEqual('ecdsa-sha2-nistp256', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA.split()[1], key.get_base64())
        self.assertEqual(256, key.get_bits())

    def test_12_compare_ecdsa(self):
        # verify that the private & public keys compare equal
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa.key'))
        self.assertEqual(key, key)
        pub = ECDSAKey(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_13_sign_ecdsa(self):
        # verify that the rsa private key can sign and verify
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa.key'))
        msg = key.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ecdsa-sha2-nistp256', msg.get_text())
        # ECDSA signatures, like DSS signatures, tend to be different
        # each time, so we can't compare against a "known correct"
        # signature.
        # Even the length of the signature can change.

        msg.rewind()
        pub = ECDSAKey(data=key.asbytes())
        self.assertTrue(pub.verify_ssh_sig(b'ice weasels', msg))

    def test_salt_size(self):
        # Read an existing encrypted private key
        file_ = test_path('test_rsa_password.key')
        password = 'television'
        newfile = file_ + '.new'
        newpassword = 'radio'
        key = RSAKey(filename=file_, password=password)
        # Write out a newly re-encrypted copy with a new password.
        # When the bug under test exists, this will ValueError.
        try:
            key.write_private_key_file(newfile, password=newpassword)
            # Verify the inner key data still matches (when no ValueError)
            key2 = RSAKey(filename=newfile, password=newpassword)
            self.assertEqual(key, key2)
        finally:
            os.remove(newfile)
