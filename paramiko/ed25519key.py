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

import nacl.signing

import six

from paramiko.message import Message
from paramiko.pkey import PKey


OPENSSH_AUTH_MAGIC = "openssh-key-v1\x00"

def unpad(data):
    padding_length = six.indexbytes(data, -1)
    if padding_length > 16:
        raise SSHException('Invalid key')
    for i in range(1, padding_length + 1):
        if six.indexbytes(data, -i) != (padding_length - i + 1):
            raise SSHException('Invalid key')
    return data[:-padding_length]


class Ed25519Key(PKey):
    def __init__(self, msg=None, data=None, filename=None, password=None):
        verifying_key = signing_key = None
        if msg is None and data is not None:
            msg = Message(data)
        if msg is not None:
            if msg.get_text() != "ssh-ed25519":
                raise SSHException('Invalid key')
            verifying_key = nacl.signing.VerifyKey(msg.get_bytes(32))
        elif filename is not None:
            with open(filename, "rb") as f:
                data = self._read_private_key("OPENSSH", f)
                signing_key = self._parse_signing_key_data(data)

        if signing_key is None and verifying_key is None:
            import pdb; pdb.set_trace()

        self._signing_key = signing_key
        self._verifying_key = verifying_key


    def _parse_signing_key_data(self, data):
        # We may eventually want this to be usable for other key types, as
        # OpenSSH moves to it, but for now this is just for Ed25519 keys.
        message = Message(data)
        if message.get_bytes(len(OPENSSH_AUTH_MAGIC)) != OPENSSH_AUTH_MAGIC:
            raise SSHException('Invalid key')

        ciphername = message.get_string()
        kdfname = message.get_string()
        kdfoptions = message.get_string()
        num_keys = message.get_int()

        if ciphername != "none" or kdfname != "none" or kdfoptions:
            raise NotImplementedError("Encrypted keys are not implemented")

        public_keys = []
        for _ in range(num_keys):
            # We don't need the public keys, fast-forward through them.
            pubkey = Message(message.get_binary())
            if pubkey.get_string() != 'ssh-ed25519':
                raise SSHException('Invalid key')
            public_keys.append(pubkey.get_binary())

        message = Message(unpad(message.get_binary()))
        if message.get_int() != message.get_int():
            raise SSHException('Invalid key')

        signing_keys = []
        for i in range(num_keys):
            if message.get_string() != 'ssh-ed25519':
                raise SSHException('Invalid key')
            # A copy of the public key, again, ignore.
            public = message.get_binary()
            key_data = message.get_binary()
            # The second half of the key data is yet another copy of the public
            # key...
            signing_key = nacl.signing.SigningKey(key_data[:32])
            assert (
                signing_key.verify_key.encode() == public == public_keys[i] == key_data[32:]
            )
            signing_keys.append(signing_key)
            # Comment, ignore.
            message.get_string()

        if len(signing_keys) != 1:
            raise SSHException('Invalid key')
        return signing_keys[0]

    def asbytes(self):
        m = Message()
        m.add_string('ssh-ed25519')
        m.add_bytes(self._signing_key.verify_key.encode())
        return m.asbytes()

    def get_name(self):
        return "ssh-ed25519"

    def get_bits(self):
        return 256

    def can_sign(self):
        return self._signing_key is not None

    def sign_ssh_data(self, data):
        m = Message()
        m.add_string('ssh-ed25519')
        m.add_string(self._signing_key.sign(data).signature)
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != 'ssh-ed25519':
            return False

        try:
            self._verifying_key.verify(data, msg.get_binary())
        except nacl.exceptions.BadSignatureError:
            return False
        else:
            return True
