# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
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
RSA keys.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException

SHA1_DIGESTINFO = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'


class RSAKey(PKey):
    """
    Representation of an RSA key which can be used to sign and verify SSH2
    data.
    """

    def __init__(self, msg=None, data=None, filename=None, password=None, key=None, file_obj=None):
        self.key = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if (msg is None) and (data is not None):
            msg = Message(data)
        if key is not None:
            self.key = key
        else:
            if msg is None:
                raise SSHException('Key object may not be empty')
            if msg.get_text() != 'ssh-rsa':
                raise SSHException('Invalid key')
            self.key = rsa.RSAPublicNumbers(
                e=msg.get_mpint(), n=msg.get_mpint()
            ).public_key(default_backend())

    @property
    def size(self):
        return self.key.key_size

    def asbytes(self):
        public_numbers = self.key.public_numbers()
        m = Message()
        m.add_string('ssh-rsa')
        m.add_mpint(public_numbers.e)
        m.add_mpint(public_numbers.n)
        return m.asbytes()

    def __str__(self):
        return self.asbytes()

    def __hash__(self):
        public_numbers = self.key.public_numbers()
        h = hash(self.get_name())
        h = h * 37 + hash(public_numbers.e)
        h = h * 37 + hash(public_numbers.n)
        return hash(h)

    def get_name(self):
        return 'ssh-rsa'

    def get_bits(self):
        return self.size

    def can_sign(self):
        return self.d is not None

    def sign_ssh_data(self, data):
        signer = self.key.signer(
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA1(),
        )
        signer.update(data)
        sig = signer.finalize()

        m = Message()
        m.add_string('ssh-rsa')
        m.add_string(sig)
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != 'ssh-rsa':
            return False
        verifier = self.key.verifier(
            signature=msg.get_binary(),
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA1(),
        )
        verifier.update(data)
        try:
            verifier.verify()
        except InvalidSignature:
            return False
        else:
            return True

    def write_private_key_file(self, filename, password=None):
        self._write_private_key_file(
            filename,
            self.key,
            serialization.PrivateFormat.TraditionalOpenSSL,
            password=password
        )

    def write_private_key(self, file_obj, password=None):
        self._write_private_key(
            file_obj,
            self.key,
            serialization.PrivateFormat.TraditionalOpenSSL,
            password=password
        )

    @staticmethod
    def generate(bits, progress_func=None):
        """
        Generate a new private RSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param int bits: number of bits the generated key should be.
        :param function progress_func: Unused
        :return: new `.RSAKey` private key
        """
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=bits, backend=default_backend()
        )
        return RSAKey(key=key)

    ###  internals...

    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file('RSA', filename, password)
        self._decode_key(data)

    def _from_private_key(self, file_obj, password):
        data = self._read_private_key('RSA', file_obj, password)
        self._decode_key(data)

    def _decode_key(self, data):
        key = serialization.load_der_private_key(
            data, password="", backend=default_backend()
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        self.key = key
