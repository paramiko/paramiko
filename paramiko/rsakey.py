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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
RSA keys.
"""

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException


class RSAKey(PKey):
    """
    Representation of an RSA key which can be used to sign and verify SSH2
    data.
    """

    name = "ssh-rsa"
    HASHES = {
        "ssh-rsa": hashes.SHA1,
        "ssh-rsa-cert-v01@openssh.com": hashes.SHA1,
        "rsa-sha2-256": hashes.SHA256,
        "rsa-sha2-256-cert-v01@openssh.com": hashes.SHA256,
        "rsa-sha2-512": hashes.SHA512,
        "rsa-sha2-512-cert-v01@openssh.com": hashes.SHA512,
    }

    def __init__(
        self,
        msg=None,
        data=None,
        filename=None,
        password=None,
        key=None,
        file_obj=None,
    ):
        self.key = None
        self.public_blob = None
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
            self._check_type_and_load_cert(
                msg=msg,
                # NOTE: this does NOT change when using rsa2 signatures; it's
                # purely about key loading, not exchange or verification
                key_type=self.name,
                cert_type="ssh-rsa-cert-v01@openssh.com",
            )
            self.key = rsa.RSAPublicNumbers(
                e=msg.get_mpint(), n=msg.get_mpint()
            ).public_key(default_backend())

    @classmethod
    def identifiers(cls):
        return list(cls.HASHES.keys())

    @property
    def size(self):
        return self.key.key_size

    @property
    def public_numbers(self):
        if isinstance(self.key, rsa.RSAPrivateKey):
            return self.key.private_numbers().public_numbers
        else:
            return self.key.public_numbers()

    def asbytes(self):
        m = Message()
        m.add_string(self.name)
        m.add_mpint(self.public_numbers.e)
        m.add_mpint(self.public_numbers.n)
        return m.asbytes()

    def __str__(self):
        # NOTE: see #853 to explain some legacy behavior.
        # TODO 4.0: replace with a nice clean fingerprint display or something
        return self.asbytes().decode("utf8", errors="ignore")

    @property
    def _fields(self):
        return (self.get_name(), self.public_numbers.e, self.public_numbers.n)

    def get_name(self):
        return self.name

    def get_bits(self):
        return self.size

    def can_sign(self):
        return isinstance(self.key, rsa.RSAPrivateKey)

    def sign_ssh_data(self, data, algorithm=None):
        if algorithm is None:
            algorithm = self.name
        sig = self.key.sign(
            data,
            padding=padding.PKCS1v15(),
            # HASHES being just a map from long identifier to either SHA1 or
            # SHA256 - cert'ness is not truly relevant.
            algorithm=self.HASHES[algorithm](),
        )
        m = Message()
        # And here again, cert'ness is irrelevant, so it is stripped out.
        m.add_string(algorithm.replace("-cert-v01@openssh.com", ""))
        m.add_string(sig)
        return m

    def verify_ssh_sig(self, data, msg):
        sig_algorithm = msg.get_text()
        if sig_algorithm not in self.HASHES:
            return False
        key = self.key
        if isinstance(key, rsa.RSAPrivateKey):
            key = key.public_key()

        # NOTE: pad received signature with leading zeros, key.verify()
        # expects a signature of key size (e.g. PuTTY doesn't pad)
        sign = msg.get_binary()
        diff = key.key_size - len(sign) * 8
        if diff > 0:
            sign = b"\x00" * ((diff + 7) // 8) + sign

        try:
            key.verify(
                sign, data, padding.PKCS1v15(), self.HASHES[sig_algorithm]()
            )
        except InvalidSignature:
            return False
        else:
            return True

    def write_private_key_file(self, filename, password=None):
        self._write_private_key_file(
            filename,
            self.key,
            serialization.PrivateFormat.TraditionalOpenSSL,
            password=password,
        )

    def write_private_key(self, file_obj, password=None):
        self._write_private_key(
            file_obj,
            self.key,
            serialization.PrivateFormat.TraditionalOpenSSL,
            password=password,
        )

    @staticmethod
    def generate(bits, progress_func=None):
        """
        Generate a new private RSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param int bits: number of bits the generated key should be.
        :param progress_func: Unused
        :return: new `.RSAKey` private key
        """
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=bits, backend=default_backend()
        )
        return RSAKey(key=key)

    # ...internals...

    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file("RSA", filename, password)
        self._decode_key(data)

    def _from_private_key(self, file_obj, password):
        data = self._read_private_key("RSA", file_obj, password)
        self._decode_key(data)

    def _decode_key(self, data):
        pkformat, data = data
        if pkformat == self._PRIVATE_KEY_FORMAT_ORIGINAL:
            try:
                key = serialization.load_der_private_key(
                    data, password=None, backend=default_backend()
                )
            except (ValueError, TypeError, UnsupportedAlgorithm) as e:
                raise SSHException(str(e))
        elif pkformat == self._PRIVATE_KEY_FORMAT_OPENSSH:
            n, e, d, iqmp, p, q = self._uint32_cstruct_unpack(data, "iiiiii")
            public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
            key = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=d % (p - 1),
                dmq1=d % (q - 1),
                iqmp=iqmp,
                public_numbers=public_numbers,
            ).private_key(default_backend())
        else:
            self._got_bad_key_format_id(pkformat)
        assert isinstance(key, rsa.RSAPrivateKey)
        self.key = key
