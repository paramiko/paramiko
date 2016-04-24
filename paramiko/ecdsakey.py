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
from hashlib import sha256, sha384, sha512

from ecdsa import SigningKey, VerifyingKey, der, curves

from paramiko.common import four_byte, one_byte
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.py3compat import byte_chr, u
from paramiko.ssh_exception import SSHException


class _ECDSACurve(object):
    """
    Object for representing a specific ECDSA Curve (i.e. nistp256, nistp384,
    etc.). Handles the generation of the key format identifier and the
    selection of the proper hash function. Also grabs the proper curve from the
    ecdsa package.
    """
    def __init__(self, oid, nist_name, key_length):
        self.oid = oid
        self.nist_name = nist_name
        self.key_length = key_length

        # Defined in RFC 5656 6.2
        self.key_format_identifier = "ecdsa-sha2-" + self.nist_name

        # Defined in RFC 5656 6.2.1
        if self.key_length <= 256:
            self.hash_object = sha256
        elif self.key_length <= 384:
            self.hash_object = sha384
        else:
            self.hash_object = sha512

        self.curve = curves.find_curve(self.oid)


class _ECDSACurveSet(object):
    """
    A collection to hold the ECDSA curves. Allows querying by oid and by key
    format identifier. The two ways in which ECDSAKey needs to be able to look
    up curves.
    """
    def __init__(self, ecdsa_curves):
        self.ecdsa_curves = ecdsa_curves

    def get_by_oid(self, oid):
        for curve in self.ecdsa_curves:
            if curve.oid == oid:
                return curve

    def get_by_key_format_identifier(self, key_format_identifier):
        for curve in self.ecdsa_curves:
            if curve.key_format_identifier == key_format_identifier:
                return curve


class ECDSAKey (PKey):
    """
    Representation of an ECDSA key which can be used to sign and verify SSH2
    data.
    """

    _ECDSA_CURVES = _ECDSACurveSet([
        _ECDSACurve((1,2,840,10045,3,1,7), 'nistp256', 256),
        _ECDSACurve((1,3,132,0,34), 'nistp384', 384),
        _ECDSACurve((1,3,132,0,35), 'nistp521', 521),
    ])


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
            self.ecdsa_curve = self._ECDSA_CURVES.get_by_key_format_identifier(
                msg.get_text())
            if self.ecdsa_curve is None:
                raise SSHException('Invalid key')
            curvename = msg.get_text()
            if curvename != self.ecdsa_curve.nist_name:
                raise SSHException("Can't handle curve of type %s" % curvename)

            pointinfo = msg.get_binary()
            if pointinfo[0:1] != four_byte:
                raise SSHException('Point compression is being used: %s' %
                                   binascii.hexlify(pointinfo))
            self.verifying_key = VerifyingKey.from_string(pointinfo[1:],
                                                          curve=self.ecdsa_curve.curve,
                                                          validate_point=validate_point)

    def asbytes(self):
        key = self.verifying_key
        m = Message()
        m.add_string(self.ecdsa_curve.key_format_identifier)
        m.add_string(self.ecdsa_curve.nist_name)

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
        return self.ecdsa_curve.key_format_identifier

    def get_bits(self):
        return self.ecdsa_curve.key_length

    def can_sign(self):
        return self.signing_key is not None

    def sign_ssh_data(self, data):
        sig = self.signing_key.sign_deterministic(
            data, sigencode=self._sigencode,
            hashfunc=self.ecdsa_curve.hash_object)
        m = Message()
        m.add_string(self.ecdsa_curve.key_format_identifier)
        m.add_string(sig)
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != self.ecdsa_curve.key_format_identifier:
            return False
        sig = msg.get_binary()

        # verify the signature by SHA'ing the data and encrypting it
        # using the public key.
        hash_obj = self.ecdsa_curve.hash_object(data).digest()
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

    ALLOWED_PADDINGS = [one_byte, byte_chr(2) * 2, byte_chr(3) * 3, 
                        byte_chr(4) * 4, byte_chr(5) * 5, byte_chr(6) * 6,
                        byte_chr(7) * 7, byte_chr(8) * 8, byte_chr(9) * 9,
                        byte_chr(10) * 10, byte_chr(11) * 11,
                        byte_chr(12) * 12, byte_chr(13) * 13,
                        byte_chr(14) * 14, byte_chr(15) * 15]

    def _decode_key(self, data):
        s, padding = der.remove_sequence(data)
        if padding:
            if padding not in self.ALLOWED_PADDINGS:
                raise ValueError("weird padding: %s" % u(binascii.hexlify(data)))
            data = data[:-len(padding)]
        key = SigningKey.from_der(data)
        self.signing_key = key
        self.verifying_key = key.get_verifying_key()
        self.ecdsa_curve = self._ECDSA_CURVES.get_by_oid(key.curve.oid)

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
