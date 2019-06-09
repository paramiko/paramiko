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
Key exchange using DJB's Curve25519. Originally introduced in OpenSSH 6.5
"""

# Author: Dan Fuhry <dan@fuhry.com>

from hashlib import sha256

from paramiko.message import Message
from paramiko.py3compat import byte_chr, long
from paramiko.ssh_exception import SSHException
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import UnsupportedAlgorithm
from binascii import hexlify

# x25519 was added in cryptography 2.0, but we support down to cryptography 1.5
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
except ImportError:
    x25519 = None

_MSG_KEXC25519_INIT, _MSG_KEXC25519_REPLY = range(30, 32)
c_MSG_KEXC25519_INIT, c_MSG_KEXC25519_REPLY = [
    byte_chr(c) for c in range(30, 32)
]


class KexCurve25519(object):
    name = "curve25519-sha256@libssh.org"
    hash_algo = sha256
    K = None

    def __init__(self, transport):
        self.transport = transport

        self.P = long(0)
        # Client public key
        self.Q_C = None
        # Server public key
        self.Q_S = None

    def start_kex(self):
        self._generate_key_pair()
        if self.transport.server_mode:
            self.transport._expect_packet(_MSG_KEXC25519_INIT)
            return
        m = Message()
        m.add_byte(c_MSG_KEXC25519_INIT)
        Q_C_bytes = self.Q_C.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        m.add_string(Q_C_bytes)
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEXC25519_REPLY)

    def parse_next(self, ptype, m):
        if self.transport.server_mode and (ptype == _MSG_KEXC25519_INIT):
            return self._parse_kexc25519_init(m)
        elif not self.transport.server_mode and (
            ptype == _MSG_KEXC25519_REPLY
        ):

            return self._parse_kexc25519_reply(m)
        msg = "KexCurve25519 asked to handle packet type {:d}"
        raise SSHException(msg.format(ptype))

    @staticmethod
    def is_supported():
        """
        Check if the openssl version pyca-cryptography is linked against
        supports curve25519 key agreement, and if cryptography itself is of a
        sufficient version for x25519 support.

        Returns True if cryptography and OpenSSL both support x25519 keys, and
        False otherwise.
        """
        if x25519 is None:
            return False  # cryptography < 2.0

        if not hasattr(Encoding, 'Raw'):
            return False  # cryptography < 2.5

        try:
            x25519.X25519PublicKey.from_public_bytes(b"\x00" * 32)
        except UnsupportedAlgorithm:
            return False  # openssl < 1.1.0

        return True

    is_available = is_supported  # for compatibility with upstream's variant

    # ...internals...

    def _generate_key_pair(self):
        while True:
            self.P = x25519.X25519PrivateKey.generate()
            pub = self.P.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            if len(pub) != 32:
                continue

            if self.transport.server_mode:
                self.Q_S = self.P.public_key()
            else:
                self.Q_C = self.P.public_key()
            break

    def _parse_kexc25519_reply(self, m):
        # client mode

        # 3 fields in response:
        #   - KEX host key
        #   - Ephemeral (Curve25519) key
        #   - Signature
        K_S = m.get_string()
        self.Q_S = x25519.X25519PublicKey.from_public_bytes(m.get_string())
        sig = m.get_binary()

        # Compute shared secret
        K = self.P.exchange(self.Q_S)
        K = long(hexlify(K), 16)

        hm = Message()
        hm.add(
            self.transport.local_version,
            self.transport.remote_version,
            self.transport.local_kex_init,
            self.transport.remote_kex_init,
        )

        # "hm" is used as the initial transport key
        hm.add_string(K_S)
        hm.add_string(
            self.Q_C.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
        )
        hm.add_string(
            self.Q_S.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
        )
        hm.add_mpint(K)
        self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())
        # Verify that server signed kex message with its own pubkey
        self.transport._verify_key(K_S, sig)
        self.transport._activate_outbound()

    def _parse_kexc25519_init(self, m):
        # server mode

        # Only one field in the client's message, which is their public key
        Q_C_bytes = m.get_string()
        self.Q_C = x25519.X25519PublicKey.from_public_bytes(Q_C_bytes)

        # Compute shared secret
        K = self.P.exchange(self.Q_C)
        K = long(hexlify(K), 16)

        # Prepare hostkey
        K_S = self.transport.get_server_key().asbytes()

        # Compute initial transport key
        hm = Message()
        hm.add(
            self.transport.remote_version,
            self.transport.local_version,
            self.transport.remote_kex_init,
            self.transport.local_kex_init,
        )

        hm.add_string(K_S)
        hm.add_string(Q_C_bytes)
        hm.add_string(
            self.Q_S.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
        )
        hm.add_mpint(K)
        H = self.hash_algo(hm.asbytes()).digest()
        self.transport._set_K_H(K, H)

        # Compute signature
        sig = self.transport.get_server_key().sign_ssh_data(H)
        # construct reply
        m = Message()
        m.add_byte(c_MSG_KEXC25519_REPLY)
        m.add_string(K_S)
        m.add_string(
            self.Q_S.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
        )
        m.add_string(sig)
        self.transport._send_message(m)
        self.transport._activate_outbound()
