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

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
except ImportError:
    x25519 = None

import paramiko.util
from paramiko.kex_group1 import KexGroup1
from paramiko.kex_group14 import KexGroup14SHA256
from paramiko.kex_gex import KexGex, KexGexSHA256
from paramiko import Message
from paramiko.common import byte_chr
from paramiko.kex_ecdh_nist import KexNistp256, _ecdh_from_encoded_point
from paramiko.kex_group16 import KexGroup16SHA512
from paramiko.kex_curve25519 import KexCurve25519


def dummy_urandom(n):
    return byte_chr(0xcc) * n


def dummy_generate_key_pair(obj):
    private_key_value = 94761803665136558137557783047955027733968423115106677159790289642479432803037  # noqa: E501
    public_key_numbers = "042bdab212fa8ba1b7c843301682a4db424d307246c7e1e6083c41d9ca7b098bf30b3d63e2ec6278488c135360456cc054b3444ecc45998c08894cbc1370f5f989"  # noqa: E501
    public_key_numbers_obj = _ecdh_from_encoded_point(
        ec.SECP256R1(), unhexlify(public_key_numbers)
    ).public_numbers()
    obj.P = ec.EllipticCurvePrivateNumbers(
        private_value=private_key_value, public_numbers=public_key_numbers_obj
    ).private_key(default_backend())
    if obj.transport.server_mode:
        obj.Q_S = _ecdh_from_encoded_point(
            ec.SECP256R1(), unhexlify(public_key_numbers)
        )
        return
    obj.Q_C = _ecdh_from_encoded_point(
        ec.SECP256R1(), unhexlify(public_key_numbers)
    )


def dummy_generate_key_curve25519(obj):
    private_key_value = unhexlify(
        b"2184abc7eb3e656d2349d2470ee695b570c227340c2b2863b6c9ff427af1f040"
    )
    obj.P = x25519.X25519PrivateKey.from_private_bytes(private_key_value)

    if obj.transport.server_mode:
        obj.Q_S = obj.P.public_key()
    else:
        obj.Q_C = obj.P.public_key()


class FakeKey (object):
    def __str__(self):
        return 'fake-key'

    def asbytes(self):
        return b'fake-key'

    def sign_ssh_data(self, H):
        return b'fake-sig'


class FakeModulusPack (object):
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa: E501
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

    K = 14730343317708716439807310032871972459448364195094179797249681733965528989482751523943515690110179031004049109375612685505881911274101441415545039654102474376472240501616988799699744135291070488314748284283496055223852115360852283821334858541043710301057312858051901453919067023103730011648890038847384890504  # noqa: E501

    def setUp(self):
        self._original_urandom = os.urandom
        os.urandom = dummy_urandom
        self._original_generate_key_pair = KexNistp256._generate_key_pair
        KexNistp256._generate_key_pair = dummy_generate_key_pair
        KexCurve25519._generate_key_pair = dummy_generate_key_curve25519

    def tearDown(self):
        os.urandom = self._original_urandom
        KexNistp256._generate_key_pair = self._original_generate_key_pair

    def test_group1_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGroup1(transport)
        kex.start_kex()
        x = b'1E000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'  # noqa: E501
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

    def test_group1_server(self):
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
        x = b'1F0000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'  # noqa: E501
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_gex_client(self):
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
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'  # noqa: E501
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

    def test_gex_old_client(self):
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
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'  # noqa: E501
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

    def test_gex_server(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGex(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD),
            transport._expect,
        )
        msg = Message()
        msg.add_int(1024)
        msg.add_int(2048)
        msg.add_int(4096)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'  # noqa: E501
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581  # noqa: E501
        H = b'CE754197C21BF3452863B4F44D0B3951F12516EF'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'  # noqa: E501
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_gex_server_with_old_client(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGex(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD),
            transport._expect,
        )
        msg = Message()
        msg.add_int(2048)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'  # noqa: E501
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581  # noqa: E501
        H = b'B41A06B2E59043CEFC1AE16EC31F1E2D12EC455B'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'  # noqa: E501
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_gex_sha256_client(self):
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
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'  # noqa: E501
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

    def test_gex_sha256_old_client(self):
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
        x = b'20000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D4'  # noqa: E501
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

    def test_gex_sha256_server(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGexSHA256(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD),
            transport._expect,
        )
        msg = Message()
        msg.add_int(1024)
        msg.add_int(2048)
        msg.add_int(4096)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'  # noqa: E501
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581  # noqa: E501
        H = b'CCAC0497CF0ABA1DBF55E1A3995D17F4CC31824B0E8D95CDF8A06F169D050D80'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'  # noqa: E501
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_gex_sha256_server_with_old_client(self):
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexGexSHA256(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD),
            transport._expect,
        )
        msg = Message()
        msg.add_int(2048)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD, msg)
        x = b'1F0000008100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0000000102'  # noqa: E501
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect)

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 67592995013596137876033460028393339951879041140378510871612128162185209509220726296697886624612526735888348020498716482757677848959420073720160491114319163078862905400020959196386947926388406687288901564192071077389283980347784184487280885335302632305026248574716290537036069329724382811853044654824945750581  # noqa: E501
        H = b'3DDD2AD840AD095E397BA4D0573972DC60F6461FD38A187CACA6615A5BC8ADBB'
        x = b'210000000866616B652D6B6579000000807E2DDB1743F3487D6545F04F1C8476092FB912B013626AB5BCEB764257D88BBA64243B9F348DF7B41B8C814A995E00299913503456983FFB9178D3CD79EB6D55522418A8ABF65375872E55938AB99A84A0B5FC8A1ECC66A7C3766E7E0F80B7CE2C9225FC2DD683F4764244B72963BBB383F529DCF0C5D17740B8A2ADBE9208D40000000866616B652D736967'  # noqa: E501
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_kex_nistp256_client(self):
        K = 91610929826364598472338906427792435253694642563583721654249504912114314269754
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexNistp256(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_ecdh_nist._MSG_KEXECDH_REPLY,), transport._expect)

        # fake reply
        msg = Message()
        msg.add_string('fake-host-key')
        Q_S = unhexlify("043ae159594ba062efa121480e9ef136203fa9ec6b6e1f8723a321c16e62b945f573f3b822258cbcd094b9fa1c125cbfe5f043280893e66863cc0cb4dccbe70210")  # noqa: E501
        msg.add_string(Q_S)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_ecdh_nist._MSG_KEXECDH_REPLY, msg)
        H = b'BAF7CE243A836037EB5D2221420F35C02B9AB6C957FE3BDE3369307B9612570A'
        self.assertEqual(K, kex.transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_kex_nistp256_server(self):
        K = 91610929826364598472338906427792435253694642563583721654249504912114314269754
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexNistp256(transport)
        kex.start_kex()
        self.assertEqual((paramiko.kex_ecdh_nist._MSG_KEXECDH_INIT,), transport._expect)

        # fake init
        msg = Message()
        Q_C = unhexlify("043ae159594ba062efa121480e9ef136203fa9ec6b6e1f8723a321c16e62b945f573f3b822258cbcd094b9fa1c125cbfe5f043280893e66863cc0cb4dccbe70210")  # noqa: E501
        H = b'2EF4957AFD530DD3F05DBEABF68D724FACC060974DA9704F2AEE4C3DE861E7CA'
        msg.add_string(Q_C)
        msg.rewind()
        kex.parse_next(paramiko.kex_ecdh_nist._MSG_KEXECDH_INIT, msg)
        self.assertEqual(K, transport._K)
        self.assertTrue(transport._activated)
        self.assertEqual(H, hexlify(transport._H).upper())

    def test_kex_group14_sha256_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGroup14SHA256(transport)
        kex.start_kex()
        x = b'1E00000101009850B3A8DE3ECCD3F19644139137C93D9C11BC28ED8BE850908EE294E1D43B88B9295311EFAEF5B736A1B652EBE184CCF36CFB0681C1ED66430088FA448B83619F928E7B9592ED6160EC11D639D51C303603F930F743C646B1B67DA38A1D44598DCE6C3F3019422B898044141420E9A10C29B9C58668F7F20A40F154B2C4768FCF7A9AA7179FB6366A7167EE26DD58963E8B880A0572F641DE0A73DC74C930F7C3A0C9388553F3F8403E40CF8B95FEDB1D366596FCF3FDDEB21A0005ADA650EF1733628D807BE5ACB83925462765D9076570056E39994FB328E3108FE406275758D6BF5F32790EF15D8416BF5548164859E785DB45E7787BB0E727ADE08641ED'  # noqa: E501
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_group1._MSG_KEXDH_REPLY,), transport._expect)

        # fake "reply"
        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_group1._MSG_KEXDH_REPLY, msg)
        K = 21526936926159575624241589599003964979640840086252478029709904308461709651400109485351462666820496096345766733042945918306284902585618061272525323382142547359684512114160415969631877620660064043178086464811345023251493620331559440565662862858765724251890489795332144543057725932216208403143759943169004775947331771556537814494448612329251887435553890674764339328444948425882382475260315505741818518926349729970262019325118040559191290279100613049085709127598666890434114956464502529053036826173452792849566280474995114751780998069614898221773345705289637708545219204637224261997310181473787577166103031529148842107599  # noqa: E501
        H = b'D007C23686BE8A7737F828DC9E899F8EB5AF423F495F138437BE2529C1B8455F'
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    def test_kex_group16_sha512_client(self):
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexGroup16SHA512(transport)
        kex.start_kex()
        x = b'1E0000020100859FF55A23E0F66463561DD8BFC4764C69C05F85665B06EC9E29EF5003A53A8FA890B6A6EB624DEB55A4FB279DE7010A53580A126817E3D235B05A1081662B1500961D0625F0AAD287F1B597CBA9DB9550D9CC26355C4C59F92E613B5C21AC191F152C09A5DB46DCBA5EA58E3CA6A8B0EB7183E27FAC10106022E8521FA91240FB389060F1E1E4A355049D29DCC82921CE6588791743E4B1DEEE0166F7CC5180C3C75F3773342DF95C8C10AAA5D12975257027936B99B3DED6E6E98CF27EADEAEAE04E7F0A28071F578646B985FCE28A59CEB36287CB65759BE0544D4C4018CDF03C9078FE9CA79ECA611CB6966899E6FD29BE0781491C659FE2380E0D99D50D9CFAAB94E61BE311779719C4C43C6D223AD3799C3915A9E55076A21152DBBF911D6594296D6ECDC1B6FA71997CD29DF987B80FCA7F36BB7F19863C72BBBF839746AFBF9A5B407D468C976AA3E36FA118D3EAAD2E08BF6AE219F81F2CE2BE946337F06CC09BBFABE938A4087E413921CBEC1965ED905999B83396ECA226110CDF6EFB80F815F6489AF87561DA3857F13A7705921306D94176231FBB336B17C3724BC17A28BECB910093AB040873D5D760E8C182B88ECCE3E38DDA68CE35BD152DF7550BD908791FCCEDD1FFDF5ED2A57FFAE79599E487A7726D8A3D950B1729A08FBB60EE462A6BBE8BF0F5F0E1358129A37840FE5B3EEB8BF26E99FA222EAE83'  # noqa: E501
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual((paramiko.kex_group1._MSG_KEXDH_REPLY,), transport._expect)

        # fake "reply"
        msg = Message()
        msg.add_string('fake-host-key')
        msg.add_mpint(69)
        msg.add_string('fake-sig')
        msg.rewind()
        kex.parse_next(paramiko.kex_group1._MSG_KEXDH_REPLY, msg)
        K = 933242830095376162107925500057692534838883186615567574891154103836907630698358649443101764908667358576734565553213003142941996368306996312915844839972197961603283544950658467545799914435739152351344917376359963584614213874232577733869049670230112638724993540996854599166318001059065780674008011575015459772051180901213815080343343801745386220342919837913506966863570473712948197760657442974564354432738520446202131551650771882909329069340612274196233658123593466135642819578182367229641847749149740891990379052266213711500434128970973602206842980669193719602075489724202241641553472106310932258574377789863734311328542715212248147206865762697424822447603031087553480483833829498375309975229907460562402877655519980113688369262871485777790149373908739910846630414678346163764464587129010141922982925829457954376352735653834300282864445132624993186496129911208133529828461690634463092007726349795944930302881758403402084584307180896465875803621285362317770276493727205689466142632599776710824902573926951951209239626732358074877997756011804454926541386215567756538832824717436605031489511654178384081883801272314328403020205577714999460724519735573055540814037716770051316113795603990199374791348798218428912977728347485489266146775472  # noqa: E501
        H = b'F6E2BCC846B9B62591EFB86663D55D4769CA06B2EDABE469DF831639B2DDD5A271985011900A724CB2C87F19F347B3632A7C1536AF3D12EE463E6EA75281AF0C'  # noqa: E501
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b'fake-host-key', b'fake-sig'), transport._verify)
        self.assertTrue(transport._activated)

    @pytest.mark.skipif("not KexCurve25519.is_supported()")
    def test_kex_c25519_client(self):
        K = 71294722834835117201316639182051104803802881348227506835068888449366462300724
        transport = FakeTransport()
        transport.server_mode = False
        kex = KexCurve25519(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_curve25519._MSG_KEXC25519_REPLY,), transport._expect
        )

        # fake reply
        msg = Message()
        msg.add_string("fake-host-key")
        Q_S = unhexlify(
            "8d13a119452382a1ada8eea4c979f3e63ad3f0c7366786d6c5b54b87219bae49"
        )
        msg.add_string(Q_S)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_curve25519._MSG_KEXC25519_REPLY, msg)
        H = b"05B6F6437C0CF38D1A6C5A6F6E2558DEB54E7FC62447EBFB1E5D7407326A5475"
        self.assertEqual(K, kex.transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    @pytest.mark.skipif("not KexCurve25519.is_supported()")
    def test_kex_c25519_server(self):
        K = 71294722834835117201316639182051104803802881348227506835068888449366462300724
        transport = FakeTransport()
        transport.server_mode = True
        kex = KexCurve25519(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_curve25519._MSG_KEXC25519_INIT,), transport._expect
        )

        # fake init
        msg = Message()
        Q_C = unhexlify(
            "8d13a119452382a1ada8eea4c979f3e63ad3f0c7366786d6c5b54b87219bae49"
        )
        H = b"DF08FCFCF31560FEE639D9B6D56D760BC3455B5ADA148E4514181023E7A9B042"
        msg.add_string(Q_C)
        msg.rewind()
        kex.parse_next(paramiko.kex_curve25519._MSG_KEXC25519_INIT, msg)
        self.assertEqual(K, transport._K)
        self.assertTrue(transport._activated)
        self.assertEqual(H, hexlify(transport._H).upper())
