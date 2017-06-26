# -*- coding: utf-8 -*-
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
import base64

from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key, Message, util
from paramiko.py3compat import StringIO, byte_chr, b, bytes, PY2

from tests.util import test_path

# from openssh's ssh-keygen
PUB_RSA = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4c='
PUB_DSS = 'ssh-dss AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug6s6fgwj/oLjYbVtjAy6pl/h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65X1FyDkg6g8tvCnaNB8Xp/UUhuzHuGsMIipRxBxw9LF608EqZcj1E3ytktoW5B5OcjrkEoz3xG7C+rpIjYvAAAAFQDwz4UnmsGiSNu5iqjn3uTzwUpshwAAAIEAkxfFeY8P2wZpDjX0MimZl5wkoFQDL25cPzGBuB4OnB8NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgRmMHy4kBq1SsXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ejg4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV1BVYd0lYukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9kUgyB7+NwacIBlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwjQgE='
PUB_ECDSA_256 = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJSPZm3ZWkvk/Zx8WP+fZRZ5/NBBHnGQwR6uIC6XHGPDIHuWUzIjAwA0bzqkOUffEsbLe+uQgKl5kbc/L8KA/eo='
PUB_ECDSA_384 = 'ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBbGibQLW9AAZiGN2hEQxWYYoFaWKwN3PKSaDJSMqmIn1Z9sgRUuw8Y/w502OGvXL/wFk0i2z50l3pWZjD7gfMH7gX5TUiCzwrQkS+Hn1U2S9aF5WJp0NcIzYxXw2r4M2A=='
PUB_ECDSA_521 = 'ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACaOaFLZGuxa5AW16qj6VLypFbLrEWrt9AZUloCMefxO8bNLjK/O5g0rAVasar1TnyHE9qj4NwzANZASWjQNbc4MAG8vzqezFwLIn/kNyNTsXNfqEko9OgHZknlj2Z79dwTJcRAL4QLcT5aND0EHZLB2fAUDXiWIb2j4rg1mwPlBMiBXA=='

FINGER_RSA = '1024 60:73:38:44:cb:51:86:65:7f:de:da:a2:2b:5a:57:d5'
FINGER_DSS = '1024 44:78:f0:b9:a2:3c:c5:18:20:09:ff:75:5b:c1:d2:6c'
FINGER_ECDSA_256 = '256 25:19:eb:55:e6:a1:47:ff:4f:38:d2:75:6f:a5:d5:60'
FINGER_ECDSA_384 = '384 c1:8d:a0:59:09:47:41:8e:a8:a6:07:01:29:23:b4:65'
FINGER_ECDSA_521 = '521 44:58:22:52:12:33:16:0e:ce:0e:be:2c:7c:7e:cc:1e'
SIGNED_RSA = '20:d7:8a:31:21:cb:f7:92:12:f2:a4:89:37:f5:78:af:e6:16:b6:25:b9:97:3d:a2:cd:5f:ca:20:21:73:4c:ad:34:73:8f:20:77:28:e2:94:15:08:d8:91:40:7a:85:83:bf:18:37:95:dc:54:1a:9b:88:29:6c:73:ca:38:b4:04:f1:56:b9:f2:42:9d:52:1b:29:29:b4:4f:fd:c9:2d:af:47:d2:40:76:30:f3:63:45:0c:d9:1d:43:86:0f:1c:70:e2:93:12:34:f3:ac:c5:0a:2f:14:50:66:59:f1:88:ee:c1:4a:e9:d1:9c:4e:46:f0:0e:47:6f:38:74:f1:44:a8'

RSA_PRIVATE_OUT = """\
-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQDTj1bqB4WmayWNPB+8jVSYpZYk80Ujvj680pOTh2bORBjbIAyz
oWGW+GUjzKxTiiPvVmxFgx5wdsFvF03v34lEVVhMpouqPAYQ15N37K/ir5XY+9m/
d8ufMCkjeXsQkKqFbAlQcnWMCRnOoPHS3I4vi6hmnDDeeYTSRvfLbW0fhwIBIwKB
gBIiOqZYaoqbeD9OS9z2K9KR2atlTxGxOJPXiP4ESqP3NVScWNwyZ3NXHpyrJLa0
EbVtzsQhLn6rF+TzXnOlcipFvjsem3iYzCpuChfGQ6SovTcOjHV9z+hnpXvQ/fon
soVRZY65wKnF7IAoUwTmJS9opqgrN6kRgCd3DASAMd1bAkEA96SBVWFt/fJBNJ9H
tYnBKZGw0VeHOYmVYbvMSstssn8un+pQpUm9vlG/bp7Oxd/m+b9KWEh2xPfv6zqU
avNwHwJBANqzGZa/EpzF4J8pGti7oIAPUIDGMtfIcmqNXVMckrmzQ2vTfqtkEZsA
4rE1IERRyiJQx6EJsz21wJmGV9WJQ5kCQQDwkS0uXqVdFzgHO6S++tjmjYcxwr3g
H0CoFYSgbddOT6miqRskOQF3DZVkJT3kyuBgU2zKygz52ukQZMqxCb1fAkASvuTv
qfpH87Qq5kQhNKdbbwbmd2NxlNabazPijWuphGTdW0VfJdWfklyS2Kr+iqrs/5wV
HhathJt636Eg7oIjAkA8ht3MQ+XSl9yIJIS8gVpbPxSw5OMfw0PjVE7tBdQruiSc
nvuQES5C9BMHjF39LZiGH1iLQy7FgdHyoP+eodI7
-----END RSA PRIVATE KEY-----
"""

DSS_PRIVATE_OUT = """\
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDngaYDZ30c6/7cJgEEbtl8FgKdwhba1Z7oOrOn4MI/6C42G1bY
wMuqZf4dBCglsdq39SHrcjbE8Vq54gPSOh3g4+uV9Rcg5IOoPLbwp2jQfF6f1FIb
sx7hrDCIqUcQccPSxetPBKmXI9RN8rZLaFuQeTnI65BKM98Ruwvq6SI2LwIVAPDP
hSeawaJI27mKqOfe5PPBSmyHAoGBAJMXxXmPD9sGaQ419DIpmZecJKBUAy9uXD8x
gbgeDpwfDaFJP8owByCKREocPFfi86LjCuQkyUKOfjYMN6iHIf1oEZjB8uJAatUr
FzI0ArXtUqOhwTLwTyFuUojE5own2WYsOAGByvgfyWjsGhvckYNhI4ODpNdPlxQ8
ZamaPGPsAoGARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dAumV+ysrV1BVYd0lYukmn
jO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kpoWQnZtXrY3GZ4/it9kUgyB7+NwacI
BlXa8cMDL7Q/69o0d54U0X/NeX5QxuYR6OMJlrkQB7oiW/P/1mwjQgECFGI9QPSc
h9pT9XHqn+1rZ4bK+QGA
-----END DSA PRIVATE KEY-----
"""

ECDSA_PRIVATE_OUT_256 = """\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKB6ty3yVyKEnfF/zprx0qwC76MsMlHY4HXCnqho2eKioAoGCCqGSM49
AwEHoUQDQgAElI9mbdlaS+T9nHxY/59lFnn80EEecZDBHq4gLpccY8Mge5ZTMiMD
ADRvOqQ5R98Sxst765CAqXmRtz8vwoD96g==
-----END EC PRIVATE KEY-----
"""

ECDSA_PRIVATE_OUT_384 = """\
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBDdO8IXvlLJgM7+sNtPl7tI7FM5kzuEUEEPRjXIPQM7mISciwJPBt+
y43EuG8nL4mgBwYFK4EEACKhZANiAAQWxom0C1vQAGYhjdoREMVmGKBWlisDdzyk
mgyUjKpiJ9WfbIEVLsPGP8OdNjhr1y/8BZNIts+dJd6VmYw+4HzB+4F+U1Igs8K0
JEvh59VNkvWheViadDXCM2MV8Nq+DNg=
-----END EC PRIVATE KEY-----
"""

ECDSA_PRIVATE_OUT_521 = """\
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAprQtAS3OF6iVUkT8IowTHWicHzShGgk86EtuEXvfQnhZFKsWm6Jo
iqAr1yEaiuI9LfB3Xs8cjuhgEEfbduYr/f6gBwYFK4EEACOhgYkDgYYABACaOaFL
ZGuxa5AW16qj6VLypFbLrEWrt9AZUloCMefxO8bNLjK/O5g0rAVasar1TnyHE9qj
4NwzANZASWjQNbc4MAG8vzqezFwLIn/kNyNTsXNfqEko9OgHZknlj2Z79dwTJcRA
L4QLcT5aND0EHZLB2fAUDXiWIb2j4rg1mwPlBMiBXA==
-----END EC PRIVATE KEY-----
"""

x1234 = b'\x01\x02\x03\x04'

TEST_KEY_BYTESTR_2 = '\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01#\x00\x00\x00\x81\x00\xd3\x8fV\xea\x07\x85\xa6k%\x8d<\x1f\xbc\x8dT\x98\xa5\x96$\xf3E#\xbe>\xbc\xd2\x93\x93\x87f\xceD\x18\xdb \x0c\xb3\xa1a\x96\xf8e#\xcc\xacS\x8a#\xefVlE\x83\x1epv\xc1o\x17M\xef\xdf\x89DUXL\xa6\x8b\xaa<\x06\x10\xd7\x93w\xec\xaf\xe2\xaf\x95\xd8\xfb\xd9\xbfw\xcb\x9f0)#y{\x10\x90\xaa\x85l\tPru\x8c\t\x19\xce\xa0\xf1\xd2\xdc\x8e/\x8b\xa8f\x9c0\xdey\x84\xd2F\xf7\xcbmm\x1f\x87'
TEST_KEY_BYTESTR_3 = '\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01#\x00\x00\x00\x00ӏV\x07k%<\x1fT$E#>ғfD\x18 \x0cae#̬S#VlE\x1epvo\x17M߉DUXL<\x06\x10דw\u2bd5ٿw˟0)#y{\x10l\tPru\t\x19Π\u070e/f0yFmm\x1f'


class KeyTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def assert_keyfile_is_encrypted(self, keyfile):
        """
        A quick check that filename looks like an encrypted key.
        """
        with open(keyfile, "r") as fh:
            self.assertEqual(
                fh.readline()[:-1],
                "-----BEGIN RSA PRIVATE KEY-----"
            )
            self.assertEqual(fh.readline()[:-1], "Proc-Type: 4,ENCRYPTED")
            self.assertEqual(fh.readline()[0:10], "DEK-Info: ")

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

    def test_C_generate_ecdsa(self):
        key = ECDSAKey.generate()
        msg = key.sign_ssh_data(b'jerri blank')
        msg.rewind()
        self.assertTrue(key.verify_ssh_sig(b'jerri blank', msg))
        self.assertEqual(key.get_bits(), 256)
        self.assertEqual(key.get_name(), 'ecdsa-sha2-nistp256')

        key = ECDSAKey.generate(bits=256)
        msg = key.sign_ssh_data(b'jerri blank')
        msg.rewind()
        self.assertTrue(key.verify_ssh_sig(b'jerri blank', msg))
        self.assertEqual(key.get_bits(), 256)
        self.assertEqual(key.get_name(), 'ecdsa-sha2-nistp256')

        key = ECDSAKey.generate(bits=384)
        msg = key.sign_ssh_data(b'jerri blank')
        msg.rewind()
        self.assertTrue(key.verify_ssh_sig(b'jerri blank', msg))
        self.assertEqual(key.get_bits(), 384)
        self.assertEqual(key.get_name(), 'ecdsa-sha2-nistp384')

        key = ECDSAKey.generate(bits=521)
        msg = key.sign_ssh_data(b'jerri blank')
        msg.rewind()
        self.assertTrue(key.verify_ssh_sig(b'jerri blank', msg))
        self.assertEqual(key.get_bits(), 521)
        self.assertEqual(key.get_name(), 'ecdsa-sha2-nistp521')

    def test_10_load_ecdsa_256(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_256.key'))
        self.assertEqual('ecdsa-sha2-nistp256', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA_256.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA_256.split()[1], key.get_base64())
        self.assertEqual(256, key.get_bits())

        s = StringIO()
        key.write_private_key(s)
        self.assertEqual(ECDSA_PRIVATE_OUT_256, s.getvalue())
        s.seek(0)
        key2 = ECDSAKey.from_private_key(s)
        self.assertEqual(key, key2)

    def test_11_load_ecdsa_password_256(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_password_256.key'), b'television')
        self.assertEqual('ecdsa-sha2-nistp256', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA_256.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA_256.split()[1], key.get_base64())
        self.assertEqual(256, key.get_bits())

    def test_12_compare_ecdsa_256(self):
        # verify that the private & public keys compare equal
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_256.key'))
        self.assertEqual(key, key)
        pub = ECDSAKey(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_13_sign_ecdsa_256(self):
        # verify that the rsa private key can sign and verify
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_256.key'))
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

    def test_14_load_ecdsa_384(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_384.key'))
        self.assertEqual('ecdsa-sha2-nistp384', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA_384.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA_384.split()[1], key.get_base64())
        self.assertEqual(384, key.get_bits())

        s = StringIO()
        key.write_private_key(s)
        self.assertEqual(ECDSA_PRIVATE_OUT_384, s.getvalue())
        s.seek(0)
        key2 = ECDSAKey.from_private_key(s)
        self.assertEqual(key, key2)

    def test_15_load_ecdsa_password_384(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_password_384.key'), b'television')
        self.assertEqual('ecdsa-sha2-nistp384', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA_384.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA_384.split()[1], key.get_base64())
        self.assertEqual(384, key.get_bits())

    def test_16_compare_ecdsa_384(self):
        # verify that the private & public keys compare equal
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_384.key'))
        self.assertEqual(key, key)
        pub = ECDSAKey(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_17_sign_ecdsa_384(self):
        # verify that the rsa private key can sign and verify
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_384.key'))
        msg = key.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ecdsa-sha2-nistp384', msg.get_text())
        # ECDSA signatures, like DSS signatures, tend to be different
        # each time, so we can't compare against a "known correct"
        # signature.
        # Even the length of the signature can change.

        msg.rewind()
        pub = ECDSAKey(data=key.asbytes())
        self.assertTrue(pub.verify_ssh_sig(b'ice weasels', msg))

    def test_18_load_ecdsa_521(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_521.key'))
        self.assertEqual('ecdsa-sha2-nistp521', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA_521.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA_521.split()[1], key.get_base64())
        self.assertEqual(521, key.get_bits())

        s = StringIO()
        key.write_private_key(s)
        # Different versions of OpenSSL (SSLeay versions 0x1000100f and
        # 0x1000207f for instance) use different apparently valid (as far as
        # ssh-keygen is concerned) padding. So we can't check the actual value
        # of the pem encoded key.
        s.seek(0)
        key2 = ECDSAKey.from_private_key(s)
        self.assertEqual(key, key2)

    def test_19_load_ecdsa_password_521(self):
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_password_521.key'), b'television')
        self.assertEqual('ecdsa-sha2-nistp521', key.get_name())
        exp_ecdsa = b(FINGER_ECDSA_521.split()[1].replace(':', ''))
        my_ecdsa = hexlify(key.get_fingerprint())
        self.assertEqual(exp_ecdsa, my_ecdsa)
        self.assertEqual(PUB_ECDSA_521.split()[1], key.get_base64())
        self.assertEqual(521, key.get_bits())

    def test_20_compare_ecdsa_521(self):
        # verify that the private & public keys compare equal
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_521.key'))
        self.assertEqual(key, key)
        pub = ECDSAKey(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_21_sign_ecdsa_521(self):
        # verify that the rsa private key can sign and verify
        key = ECDSAKey.from_private_key_file(test_path('test_ecdsa_521.key'))
        msg = key.sign_ssh_data(b'ice weasels')
        self.assertTrue(type(msg) is Message)
        msg.rewind()
        self.assertEqual('ecdsa-sha2-nistp521', msg.get_text())
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
            self.assert_keyfile_is_encrypted(newfile)
            # Verify the inner key data still matches (when no ValueError)
            key2 = RSAKey(filename=newfile, password=newpassword)
            self.assertEqual(key, key2)
        finally:
            os.remove(newfile)

    def test_stringification(self):
        key = RSAKey.from_private_key_file(test_path('test_rsa.key'))
        comparable = TEST_KEY_BYTESTR_2 if PY2 else TEST_KEY_BYTESTR_3
        self.assertEqual(str(key), comparable)

    def test_ed25519(self):
        key1 = Ed25519Key.from_private_key_file(test_path('test_ed25519.key'))
        key2 = Ed25519Key.from_private_key_file(
            test_path('test_ed25519_password.key'), b'abc123'
        )
        self.assertNotEqual(key1.asbytes(), key2.asbytes())

    def test_ed25519_compare(self):
        # verify that the private & public keys compare equal
        key = Ed25519Key.from_private_key_file(test_path('test_ed25519.key'))
        self.assertEqual(key, key)
        pub = Ed25519Key(data=key.asbytes())
        self.assertTrue(key.can_sign())
        self.assertTrue(not pub.can_sign())
        self.assertEqual(key, pub)

    def test_keyfile_is_actually_encrypted(self):
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
            self.assert_keyfile_is_encrypted(newfile)
        finally:
            os.remove(newfile)
