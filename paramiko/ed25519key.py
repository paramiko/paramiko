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

try:
    import nacl.signing
    import nacl.exceptions
except ImportError:
    nacl = None

from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException


class Ed25519Key(PKey):
    """
    Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.

    .. note::
        Ed25519 key support was added to OpenSSH in version 6.5.

    .. versionadded:: 2.2
    .. versionchanged:: 2.3
        Added a ``file_obj`` parameter to match other key classes.
    """

    @staticmethod
    def is_supported():
        return nacl is not None

    def __init__(self, msg=None, data=None, filename=None, password=None, file_obj=None):
        if nacl is None:
            raise SSHException("Missing dependency PyNaCl")
        self.public_blob = None
        verifying_key = None
        signing_key = None
        pkformat = None

        if msg is None and data is not None:
            msg = Message(data)
        if msg is not None:
            self._check_type_and_load_cert(
                msg=msg,
                key_type="ssh-ed25519",
                cert_type="ssh-ed25519-cert-v01@openssh.com",
            )
            verifying_key = nacl.signing.VerifyKey(msg.get_binary())
        elif filename is not None:
            pkformat, data = self._read_private_key_file('-', 'ssh-ed25519', filename, password)
        elif file_obj is not None:
            pkformat, data = self._read_private_key('-', 'ssh-ed25519', file_obj, password)
        if filename or file_obj:
            if pkformat != self.FORMAT_OPENSSH:
                raise SSHException("Invalid key format")
            signing_key = self._parse_signing_key_data(data)

        if signing_key is None and verifying_key is None:
            raise ValueError("need a key")
        self._signing_key = signing_key
        self._verifying_key = verifying_key

    def _parse_signing_key_data(self, data):
        message = Message(data)
        public = message.get_binary()
        key_data = message.get_binary()
        # The second half of the key data is yet another copy of the public key...
        signing_key = nacl.signing.SigningKey(key_data[:32])
        # Verify that all the public keys are the same...
        if not signing_key.verify_key.encode() == public == key_data[32:]:
            raise SSHException("Invalid key public part mis-match")
        comment = message.get_binary()  # noqa: F841
        return signing_key

    def asbytes(self):
        if self.can_sign():
            v = self._signing_key.verify_key
        else:
            v = self._verifying_key
        m = Message()
        m.add_string("ssh-ed25519")
        m.add_string(v.encode())
        return m.asbytes()

    def __hash__(self):
        if self.can_sign():
            v = self._signing_key.verify_key
        else:
            v = self._verifying_key
        return hash((self.get_name(), v))

    def get_name(self):
        return "ssh-ed25519"

    def get_bits(self):
        return 256

    def can_sign(self):
        return self._signing_key is not None

    def sign_ssh_data(self, data):
        m = Message()
        m.add_string("ssh-ed25519")
        m.add_string(self._signing_key.sign(data).signature)
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != "ssh-ed25519":
            return False

        try:
            self._verifying_key.verify(data, msg.get_binary())
        except nacl.exceptions.BadSignatureError:
            return False
        else:
            return True
