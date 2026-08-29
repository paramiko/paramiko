"""
ML-KEM hybrid key exchange for SSH.

Implements the post-quantum / classical hybrid key agreement methods
described in draft-ietf-sshm-mlkem-hybrid-kex (e.g.
``mlkem768x25519-sha256``).

Each method combines an ML-KEM key encapsulation with a traditional
ECDH/X25519 key agreement; the final shared secret is the hash of the
two component secrets concatenated together.
"""

import hashlib
from typing import TYPE_CHECKING

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
except ImportError:  # pragma: no cover - cryptography <48
    mlkem = None

from paramiko.common import byte_chr
from paramiko.message import Message
from paramiko.ssh_exception import SSHException

if TYPE_CHECKING:
    from paramiko.transport import Transport

# Per draft-ietf-sshm-mlkem-hybrid-kex, the hybrid kex reuses message
# numbers 30 and 31 (named SSH_MSG_KEX_HYBRID_INIT / _REPLY).
_MSG_KEX_HYBRID_INIT, _MSG_KEX_HYBRID_REPLY = range(30, 32)
c_MSG_KEX_HYBRID_INIT, c_MSG_KEX_HYBRID_REPLY = [
    byte_chr(c) for c in range(30, 32)
]


class KexMLKEM768X25519:
    """
    ``mlkem768x25519-sha256`` hybrid key exchange.

    Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is
    ``SHA-256(K_PQ || K_CL)`` where ``K_PQ`` is the ML-KEM secret and
    ``K_CL`` is the X25519 shared secret.
    """

    name = "mlkem768x25519-sha256"
    hash_algo = hashlib.sha256
    # Fixed sizes from FIPS 203 (ML-KEM-768) and RFC 7748 (X25519).
    _MLKEM_PUBKEY_BYTES = 1184
    _MLKEM_CIPHERTEXT_BYTES = 1088
    _X25519_PUBKEY_BYTES = 32
    _C_INIT_BYTES = _MLKEM_PUBKEY_BYTES + _X25519_PUBKEY_BYTES
    _S_REPLY_BYTES = _MLKEM_CIPHERTEXT_BYTES + _X25519_PUBKEY_BYTES

    def __init__(self, transport: Transport):
        self.transport = transport
        # Client-side: our ML-KEM decapsulation key. Server-side: unused.
        self.mlkem_key = None
        # Our ephemeral X25519 private key (both roles).
        self.x25519_key = None

    @classmethod
    def is_available(cls):
        if mlkem is None:
            return False
        try:
            mlkem.MLKEM768PrivateKey.generate()
            X25519PrivateKey.generate()
        except UnsupportedAlgorithm:
            return False
        return True

    # ---- protocol entry points ---------------------------------------

    def start_kex(self):
        self.x25519_key = X25519PrivateKey.generate()
        if self.transport.server_mode:
            self.transport._expect_packet(_MSG_KEX_HYBRID_INIT)
            return
        self.mlkem_key = mlkem.MLKEM768PrivateKey.generate()
        c_init = (
            self.mlkem_key.public_key().public_bytes_raw()
            + self.x25519_key.public_key().public_bytes_raw()
        )
        m = Message()
        m.add_byte(c_MSG_KEX_HYBRID_INIT)
        m.add_string(c_init)
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEX_HYBRID_REPLY)

    def parse_next(self, ptype, m):
        if self.transport.server_mode and ptype == _MSG_KEX_HYBRID_INIT:
            return self._parse_hybrid_init(m)
        if not self.transport.server_mode and ptype == _MSG_KEX_HYBRID_REPLY:
            return self._parse_hybrid_reply(m)
        raise SSHException(
            "{} asked to handle packet type {:d}".format(
                self.__class__.__name__, ptype
            )
        )

    def _x25519_exchange(self, peer_pub_bytes):
        peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        secret = self.x25519_key.exchange(peer)
        # Per RFC 8731 (and reaffirmed by the hybrid draft), reject the
        # all-zero output that signals a small-order public value.
        if constant_time.bytes_eq(secret, b"\x00" * 32):
            raise SSHException(
                "peer's curve25519 public value has wrong order"
            )
        return secret

    # ---- server side -------------------------------------------------

    def _parse_hybrid_init(self, m):
        c_init = m.get_string()
        if len(c_init) != self._C_INIT_BYTES:
            raise SSHException(
                "Invalid C_INIT length for {}: got {}, expected {}".format(
                    self.name, len(c_init), self._C_INIT_BYTES
                )
            )
        c_pk2 = c_init[: self._MLKEM_PUBKEY_BYTES]
        c_pk1 = c_init[self._MLKEM_PUBKEY_BYTES :]

        # Encapsulate against the client's ML-KEM public key.
        client_mlkem_pub = mlkem.MLKEM768PublicKey.from_public_bytes(c_pk2)
        k_pq, s_ct2 = client_mlkem_pub.encapsulate()

        # X25519 with the client's ephemeral public value.
        k_cl = self._x25519_exchange(c_pk1)

        K_bytes = self.hash_algo(k_pq + k_cl).digest()

        s_pk1 = self.x25519_key.public_key().public_bytes_raw()
        s_reply = s_ct2 + s_pk1

        K_S = self.transport.get_server_key().asbytes()

        hm = Message()
        hm.add(
            self.transport.remote_version,
            self.transport.local_version,
            self.transport.remote_kex_init,
            self.transport.local_kex_init,
        )
        hm.add_string(K_S)
        hm.add_string(c_init)
        hm.add_string(s_reply)
        # Per the hybrid draft: K is the hash output, encoded as a string.
        hm.add_string(K_bytes)
        H = self.hash_algo(hm.asbytes()).digest()

        self.transport._set_K_H(K_bytes, H)

        sig = self.transport.get_server_key().sign_ssh_data(
            H, self.transport.host_key_type
        )

        reply = Message()
        reply.add_byte(c_MSG_KEX_HYBRID_REPLY)
        reply.add_string(K_S)
        reply.add_string(s_reply)
        reply.add_string(sig)
        self.transport._send_message(reply)
        self.transport._activate_outbound()

    # ---- client side -------------------------------------------------

    def _parse_hybrid_reply(self, m):
        K_S = m.get_string()
        s_reply = m.get_string()
        sig = m.get_binary()

        if len(s_reply) != self._S_REPLY_BYTES:
            raise SSHException(
                "Invalid S_REPLY length for {}: got {}, expected {}".format(
                    self.name, len(s_reply), self._S_REPLY_BYTES
                )
            )
        s_ct2 = s_reply[: self._MLKEM_CIPHERTEXT_BYTES]
        s_pk1 = s_reply[self._MLKEM_CIPHERTEXT_BYTES :]

        k_pq = self.mlkem_key.decapsulate(s_ct2)
        k_cl = self._x25519_exchange(s_pk1)
        K_bytes = self.hash_algo(k_pq + k_cl).digest()

        c_init = (
            self.mlkem_key.public_key().public_bytes_raw()
            + self.x25519_key.public_key().public_bytes_raw()
        )

        hm = Message()
        hm.add(
            self.transport.local_version,
            self.transport.remote_version,
            self.transport.local_kex_init,
            self.transport.remote_kex_init,
        )
        hm.add_string(K_S)
        hm.add_string(c_init)
        hm.add_string(s_reply)
        hm.add_string(K_bytes)
        H = self.hash_algo(hm.asbytes()).digest()

        self.transport._set_K_H(K_bytes, H)
        self.transport._verify_key(K_S, sig)
        self.transport._activate_outbound()
