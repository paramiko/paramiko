# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
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

"""
ECDSA keys
"""

import binascii
from hashlib import sha256

from ecdsa import SigningKey, VerifyingKey, der, curves

from paramiko.common import four_byte, one_byte
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.py3compat import byte_chr, u
from paramiko.ssh_exception import SSHException


class ECDSAKey (PKey):
    """
    Representation of an ECDSA key which can be used to sign and verify SSH2
    data.
    """

    def __init__(self, msg=None, data=None, filename=None, password=None,
                 vals=None, file_obj=None, validate_point=True):
        self.verifying_key = None
        self.signing_key = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if (msg is None) and (data is not None):
            msg = Message(data)
        if vals is not None:
            self.signing_key, self.verifying_key = vals
        else:
            if msg is None:
                raise SSHException('Key object may not be empty')
            if msg.get_text() != 'ecdsa-sha2-nistp256':
                raise SSHException('Invalid key')
            curvename = msg.get_text()
            if curvename != 'nistp256':
                raise SSHException("Can't handle curve of type %s" % curvename)

            pointinfo = msg.get_binary()
            if pointinfo[0:1] != four_byte:
                raise SSHException('Point compression is being used: %s' %
                                   binascii.hexlify(pointinfo))
            self.verifying_key = VerifyingKey.from_string(pointinfo[1:],
                                                          curve=curves.NIST256p,
                                                          validate_point=validate_point)
        self.size = 256

    def asbytes(self):
        key = self.verifying_key
        m = Message()
        m.add_string('ecdsa-sha2-nistp256')
        m.add_string('nistp256')

        point_str = four_byte + key.to_string()

        m.add_string(point_str)
        return m.asbytes()

    def __str__(self):
        return self.asbytes()

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.verifying_key.pubkey.point.x())
        h = h * 37 + hash(self.verifying_key.pubkey.point.y())
        return hash(h)

    def get_name(self):
        return 'ecdsa-sha2-nistp256'

    def get_bits(self):
        return self.size

    def can_sign(self):
        return self.signing_key is not None

    def sign_ssh_data(self, data):
        sig = self.signing_key.sign_deterministic(
            data, sigencode=self._sigencode, hashfunc=sha256)
        m = Message()
        m.add_string('ecdsa-sha2-nistp256')
        m.add_string(sig)
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != 'ecdsa-sha2-nistp256':
            return False
        sig = msg.get_binary()

        # verify the signature by SHA'ing the data and encrypting it
        # using the public key.
        hash_obj = sha256(data).digest()
        return self.verifying_key.verify_digest(sig, hash_obj,
                                                sigdecode=self._sigdecode)

    def write_private_key_file(self, filename, password=None):
        key = self.signing_key or self.verifying_key
        self._write_private_key_file('EC', filename, key.to_der(), password)

    def write_private_key(self, file_obj, password=None):
        key = self.signing_key or self.verifying_key
        self._write_private_key('EC', file_obj, key.to_der(), password)

    @staticmethod
    def generate(curve=curves.NIST256p, progress_func=None):
        """
        Generate a new private ECDSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param function progress_func: Not used for this type of key.
        :returns: A new private key (`.ECDSAKey`) object
        """
        signing_key = SigningKey.generate(curve)
        key = ECDSAKey(vals=(signing_key, signing_key.get_verifying_key()))
        return key

    ###  internals...

    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file('EC', filename, password)
        self._decode_key(data)

    def _from_private_key(self, file_obj, password):
        data = self._read_private_key('EC', file_obj, password)
        self._decode_key(data)

    ALLOWED_PADDINGS = [one_byte, byte_chr(2) * 2, byte_chr(3) * 3, byte_chr(4) * 4,
                        byte_chr(5) * 5, byte_chr(6) * 6, byte_chr(7) * 7]

    def _decode_key(self, data):
        s, padding = der.remove_sequence(data)
        if padding:
            if padding not in self.ALLOWED_PADDINGS:
                raise ValueError("weird padding: %s" % u(binascii.hexlify(data)))
            data = data[:-len(padding)]
        key = SigningKey.from_der(data)
        self.signing_key = key
        self.verifying_key = key.get_verifying_key()
        self.size = 256

    def _sigencode(self, r, s, order):
        msg = Message()
        msg.add_mpint(r)
        msg.add_mpint(s)
        return msg.asbytes()

    def _sigdecode(self, sig, order):
        msg = Message(sig)
        r = msg.get_mpint()
        s = msg.get_mpint()
        return r, s
