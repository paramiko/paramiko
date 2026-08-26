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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

from typing import Union

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher

from paramiko.message import Message
from paramiko.pkey import OPENSSH_AUTH_MAGIC, PKey, _unpad_openssh
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from paramiko.util import b


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    """
    Return the 32 raw bytes of ``key``, as used in the SSH ``ssh-ed25519``
    key blob.

    Cryptography's own ``public_bytes_raw`` is tidier, but only exists as of
    version 40; this spelling works on every version we support.
    """
    return key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class Ed25519Key(PKey):
    """
    Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.

    .. note::
        Ed25519 key support was added to OpenSSH in version 6.5.

    .. versionadded:: 2.2
    .. versionchanged:: 2.3
        Added a ``file_obj`` parameter to match other key classes.
    """

    name = "ssh-ed25519"

    def __init__(
        self, msg=None, data=None, filename=None, password=None, file_obj=None
    ):
        self.public_blob = None
        self._verifying_key, self._signing_key = None, None
        if msg is None and data is not None:
            msg = Message(data)
        if msg is not None:
            self._check_type_and_load_cert(
                msg=msg,
                key_type=self.name,
                cert_type="ssh-ed25519-cert-v01@openssh.com",
            )
            self._verifying_key = Ed25519PublicKey.from_public_bytes(
                msg.get_binary()
            )
        elif filename is not None:
            with open(filename, "r") as f:
                pkformat, data = self._read_private_key("OPENSSH", f)
        elif file_obj is not None:
            pkformat, data = self._read_private_key("OPENSSH", file_obj)

        if filename or file_obj:
            self._signing_key = self._parse_signing_key_data(data, password)

        if self._signing_key is None and self._verifying_key is None:
            raise ValueError("need a key")

    def _parse_signing_key_data(self, data, password):
        from paramiko.transport import Transport

        # We may eventually want this to be usable for other key types, as
        # OpenSSH moves to it, but for now this is just for Ed25519 keys.
        # This format is described here:
        # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
        # The description isn't totally complete, and I had to refer to the
        # source for a full implementation.
        message = Message(data)
        if message.get_bytes(len(OPENSSH_AUTH_MAGIC)) != OPENSSH_AUTH_MAGIC:
            raise SSHException("Invalid key")

        ciphername = message.get_text()
        kdfname = message.get_text()
        kdfoptions = message.get_binary()
        num_keys = message.get_int()

        if kdfname == "none":
            # kdfname of "none" must have an empty kdfoptions, the ciphername
            # must be "none"
            if kdfoptions or ciphername != "none":
                raise SSHException("Invalid key")
        elif kdfname == "bcrypt":
            if not password:
                raise PasswordRequiredException(
                    "Private key file is encrypted"
                )
            kdf = Message(kdfoptions)
            bcrypt_salt = kdf.get_binary()
            bcrypt_rounds = kdf.get_int()
        else:
            raise SSHException("Invalid key")

        if ciphername != "none" and ciphername not in Transport._cipher_info:
            raise SSHException("Invalid key")

        public_keys = []
        for _ in range(num_keys):
            pubkey = Message(message.get_binary())
            if pubkey.get_text() != self.name:
                raise SSHException("Invalid key")
            public_keys.append(pubkey.get_binary())

        private_ciphertext = message.get_binary()
        if ciphername == "none":
            private_data = private_ciphertext
        else:
            cipher = Transport._cipher_info[ciphername]
            key = bcrypt.kdf(
                password=b(password),
                salt=bcrypt_salt,
                desired_key_bytes=cipher["key-size"] + cipher["block-size"],
                rounds=bcrypt_rounds,
                # We can't control how many rounds are on disk, so no sense
                # warning about it.
                ignore_few_rounds=True,
            )
            decryptor = Cipher(
                cipher["class"](key[: cipher["key-size"]]),
                cipher["mode"](key[cipher["key-size"] :]),
                backend=default_backend(),
            ).decryptor()
            private_data = (
                decryptor.update(private_ciphertext) + decryptor.finalize()
            )

        message = Message(_unpad_openssh(private_data))
        if message.get_int() != message.get_int():
            raise SSHException("Invalid key")

        signing_keys = []
        for i in range(num_keys):
            if message.get_text() != self.name:
                raise SSHException("Invalid key")
            # A copy of the public key, again, ignore.
            public = message.get_binary()
            key_data = message.get_binary()
            # The second half of the key data is yet another copy of the public
            # key...
            signing_key = Ed25519PrivateKey.from_private_bytes(key_data[:32])
            # Verify that all the public keys are the same...
            assert (
                _public_bytes(signing_key.public_key())
                == public
                == public_keys[i]
                == key_data[32:]
            )
            signing_keys.append(signing_key)
            # Comment, ignore.
            message.get_binary()

        if len(signing_keys) != 1:
            raise SSHException("Invalid key")
        return signing_keys[0]

    def asbytes(self):
        v = self.verifying_key
        # Handle not-fully-initialized situations gracefully
        my_bytes = _public_bytes(v) if v is not None else b""
        m = Message()
        m.add_string(self.name)
        m.add_string(my_bytes)
        return m.asbytes()

    @property
    def _fields(self):
        # NOTE: this deliberately uses the key's raw bytes and not the key
        # object itself. Cryptography's key objects compare by identity on
        # older versions and are unhashable on newer ones; neither is safe
        # for the equality/hashing contract PKey relies on here.
        v = self.verifying_key
        return (self.get_name(), _public_bytes(v) if v is not None else b"")

    # TODO (backwards incompat): remove
    def get_name(self):
        return self.name

    def get_bits(self):
        return 256

    def can_sign(self):
        return self._signing_key is not None

    def can_verify(self):
        return self._verifying_key is not None

    @property
    def verifying_key(self) -> Union[Ed25519PublicKey, None]:
        if self.can_sign():
            return self._signing_key.public_key()
        elif self.can_verify():
            return self._verifying_key
        return None

    def sign_ssh_data(self, data, algorithm=None):
        m = Message()
        m.add_string(self.name)
        m.add_string(self._signing_key.sign(data))
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != self.name:
            return False

        try:
            self._verifying_key.verify(msg.get_binary(), data)
        except InvalidSignature:
            return False
        else:
            return True
