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
Some unit tests for the key exchange protocols.
"""

from binascii import hexlify, unhexlify
import os
import unittest

import paramiko.util
from paramiko.kex_group1 import KexGroup1
from paramiko.kex_gex import KexGex, KexGexSHA256
from paramiko import Message
from paramiko.common import byte_chr
from paramiko.kex_ecdh_nist import KexNistp256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


def dummy_urandom(n):
    return byte_chr(0xcc) * n

def dummy_generate_key_pair(obj):
    private_key_value = 94761803665136558137557783047955027733968423115106677159790289642479432803037
    public_key_numbers = "042bdab212fa8ba1b7c843301682a4db424d307246c7e1e6083c41d9ca7b098bf30b3d63e2ec6278488c135360456cc054b3444ecc45998c08894cbc1370f5f989"
    public_key_numbers_obj = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), unhexlify(public_key_numbers))
    obj.P = ec.EllipticCurvePrivateNumbers(private_value=private_key_value, public_numbers=public_key_numbers_obj).private_key(default_backend())
    if obj.transport.server_mode:
        obj.Q_S = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), unhexlify(public_key_numbers)).public_key(default_backend())
        return
    obj.Q_C = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), unhexlify(public_key_numbers)).public_key(default_backend())


class FakeKey (object):
    def __str__(self):
        return 'fake-key'

    def asbytes(self):
        return b'fake-key'

    def sign_ssh_data(self, H):
        return b'fake-sig'


class FakeModulusPack (object):
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    G = 2

    def get_modulus(self, min, ask, max):
        return self.G, self.P


class FakeTransport(object):
    local_version = 'SSH-2.0-paramiko_1.0'
    remote_version = 'SSH-2.0-lame'
    local_kex_init = 'local-kex-init'
    remote_kex_init = 'remote-kex-init'

    def _send_message(self, m):
        self._message = m

    def _expect_packet(self, *t):
        self._expect = t

    def _set_K_H(self, K, H):
        self._K = K
        self._H = H

    def _verify_key(self, host_key, sig):
        self._verify = (host_key, sig)

    def _activate_outbound(self):
        self._activated = True

    def _log(self, level, s):
        pass

    def get_server_key(self):
        return FakeKey()

    def _get_modulus_pack(self):
        return FakeModulusPack()


class KexTest (unittest.TestCase):

    K = 14730343317708716439807310032871972459448364195094179797249681733965528989482751523943515690110179031004049109375612685505881911274101441415545039654102474376472240501616988799699744135291070488314748284283496055223852115360852283821334858541043710301057312858051901453919067023103730011648890038847384890504

    def setUp(self):
        self._original_urandom = os.urandom
        os.urandom = dummy_urandom
        self._original_generate_key_pair = KexNistp256._generate_key_pair
        KexNistp256._generate_key_pair = dummy_generate_key_pair

    def tearDown(self):
        os.urandom = self._original_urandom
        KexNistp256._generate_key_pair = self._original_generate_key_pair

    def test_1_group1_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGroup1(transport)
        kex.start_kex()
        x = b'1E000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_group1._MSG_KEXDH_REPLY,), transport._expect)

        # fake "reply"
        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_group1._MSG_KEXDH_REPLY, msg)
        H = b'03079780F3D3AD0B3C6DB30C8D21685F367A86D2'
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_2_group1_server(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGroup1(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_group1._MSG_KEXDH_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(69)
        msg.rewind()
        kex.parse_next(paramiko.kex_group1._MSG_KEXDH_INIT, msg)
        H = b'B16BF34DD10945EDE84E9C1EF24A14BFDC843389'
        x = b'1F0000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_3_gex_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGex(transport)
        kex.start_kex()
        x = b'22000004000000080000002000'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_GROUP,), transport._expect)

        msg = Message()
        msg.add_mpint(FakeModulusPack.P)
        msg.add_mpint(FakeModulusPack.G)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, msg)
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), transport._expect)

        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REPLY, msg)
        H = b'A265563F2FA87F1A89BF007EE90D58BE2E4A4BD0'
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_4_gex_old_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGex(transport)
        kex.start_kex(_test_old_style=True)
        x = b'1E00000800'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_GROUP,), transport._expect)

        msg = Message()
        msg.add_mpint(FakeModulusPack.P)
        msg.add_mpint(FakeModulusPack.G)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, msg)
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), transport._expect)

        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REPLY, msg)
        H = b'807F87B269EF7AC5EC7E75676808776A27D5864C'
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)
        
    def test_5_gex_server(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGex(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD), transport._expect)

        msg = Message()
        msg.add_int(1024)
        msg.add_int(2048)
        msg.add_int(4096)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581
        H = b'CE754197C21BF3452863B4F44D0B3951F12516EF'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_6_gex_server_with_old_client(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGex(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD), transport._expect)

        msg = Message()
        msg.add_int(2048)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581
        H = b'B41A06B2E59043CEFC1AE16EC31F1E2D12EC455B'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_7_gex_sha256_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGexSHA256(transport)
        kex.start_kex()
        x = b'22000004000000080000002000'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_GROUP,), transport._expect)

        msg = Message()
        msg.add_mpint(FakeModulusPack.P)
        msg.add_mpint(FakeModulusPack.G)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, msg)
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), transport._expect)

        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REPLY, msg)
        H = b'AD1A9365A67B4496F05594AD1BF656E3CDA0851289A4C1AFF549FEAE50896DF4'
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_8_gex_sha256_old_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGexSHA256(transport)
        kex.start_kex(_test_old_style=True)
        x = b'1E00000800'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_GROUP,), transport._expect)

        msg = Message()
        msg.add_mpint(FakeModulusPack.P)
        msg.add_mpint(FakeModulusPack.G)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, msg)
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), transport._expect)

        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REPLY, msg)
        H = b'518386608B15891AE5237DEE08DCADDE76A0BCEFCE7F6DB3AD66BC41D256DFE5'
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_9_gex_sha256_server(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGexSHA256(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD), transport._expect)

        msg = Message()
        msg.add_int(1024)
        msg.add_int(2048)
        msg.add_int(4096)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581
        H = b'CCAC0497CF0ABA1DBF55E1A3995D17F4CC31824B0E8D95CDF8A06F169D050D80'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_10_gex_sha256_server_with_old_client(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGexSHA256(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD), transport._expect)

        msg = Message()
        msg.add_int(2048)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581
        H = b'3DDD2AD840AD095E397BA4D0573972DC60F6461FD38A187CACA6615A5BC8ADBB'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_11_kex_nistp256_client(self):
        K = 91610929826364598472338906427792435253694642563583721654249504912114314269754
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexNistp256(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_ecdh_nist._MSG_KEXECDH_REPLY,), transport._expect)

        #fake reply
        msg = Message()
        msg.add_string('fake-host-key')
        Q_S = unhexlify("043ae159594ba062efa121480e9ef136203fa9ec6b6e1f8723a321c16e62b945f573f3b822258cbcd094b9fa1c125cbfe5f043280893e66863cc0cb4dccbe70210")
        msg.add_string(Q_S)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_ecdh_nist._MSG_KEXECDH_REPLY, msg)
        H = b'BAF7CE243A836037EB5D2221420F35C02B9AB6C957FE3BDE3369307B9612570A'
        self.assertEqual(K, kex.transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_12_kex_nistp256_server(self):
        K = 91610929826364598472338906427792435253694642563583721654249504912114314269754
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexNistp256(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_ecdh_nist._MSG_KEXECDH_INIT,), transport._expect)

        #fake init
        msg=Message()
        Q_C = unhexlify("043ae159594ba062efa121480e9ef136203fa9ec6b6e1f8723a321c16e62b945f573f3b822258cbcd094b9fa1c125cbfe5f043280893e66863cc0cb4dccbe70210")
        H = b'2EF4957AFD530DD3F05DBEABF68D724FACC060974DA9704F2AEE4C3DE861E7CA'
        msg.add_string(Q_C)
        msg.rewind()
        kex.parse_next(paramiko.kex_ecdh_nist._MSG_KEXECDH_INIT, msg)
        self.assertEqual(K, transport._K)
        self.assertTrue(transport._activated)
        self.assertEqual(H, hexlify(transport._H).upper())
