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

import base64
import binascii
import textwrap

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_rfc6979_signature, encode_rfc6979_signature
)

from pyasn1.codec.der import encoder
from pyasn1.type import namedtype, namedval, tag, univ

from paramiko.common import four_byte, one_byte, zero_byte
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.py3compat import byte_chr
from paramiko.ssh_exception import SSHException
from paramiko.util import deflate_long, inflate_long


# RFC 5480, section 2.1.1
class _ECParameters(univ.Choice):
    # TODO: There are a few more options for this choice I think, the RFC says
    # not to use them though...
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("namedCurve", univ.ObjectIdentifier()),
    )


# RFC 5915, Appendix A
class _ECPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "version",
            univ.Integer(
                namedValues=namedval.NamedValues(
                    ("ecPrivkeyVer1", 1),
                )
            ),
        ),
        namedtype.NamedType("privateKey", univ.OctetString()),
        namedtype.OptionalNamedType("parameters", _ECParameters().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0),
        )),
        namedtype.OptionalNamedType("publicKey", univ.BitString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1),
        )),
    )


_CURVE_TO_OID = {
    ec.SECP256R1: univ.ObjectIdentifier("1.2.840.10045.3.1.7")
}

class ECDSAKey(PKey):
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
            curve = ec.SECP256R1()
            numbers = ec.EllipticCurvePublicNumbers(
                x=inflate_long(pointinfo[1:1 + curve.key_size // 8], always_positive=True),
                y=inflate_long(pointinfo[1 + curve.key_size // 8:], always_positive=True),
                curve=curve
            )
            self.verifying_key = numbers.public_key(backend=default_backend())
        self.size = 256

    def asbytes(self):
        key = self.verifying_key
        m = Message()
        m.add_string('ecdsa-sha2-nistp256')
        m.add_string('nistp256')

        numbers = key.public_numbers()

        x_bytes = deflate_long(numbers.x, add_sign_padding=False)
        x_bytes = b'\x00' * (len(x_bytes) - key.curve.key_size // 8) + x_bytes

        y_bytes = deflate_long(numbers.y, add_sign_padding=False)
        y_bytes = b'\x00' * (len(y_bytes) - key.curve.key_size // 8) + y_bytes

        point_str = four_byte + x_bytes + y_bytes
        m.add_string(point_str)
        return m.asbytes()

    def __str__(self):
        return self.asbytes()

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.verifying_key.public_numbers().x)
        h = h * 37 + hash(self.verifying_key.public_numbers().y)
        return hash(h)

    def get_name(self):
        return 'ecdsa-sha2-nistp256'

    def get_bits(self):
        return self.size

    def can_sign(self):
        return self.signing_key is not None

    def sign_ssh_data(self, data):
        signer = self.signing_key.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(data)
        sig = signer.finalize()
        r, s = decode_rfc6979_signature(sig)

        m = Message()
        m.add_string('ecdsa-sha2-nistp256')
        m.add_string(self._sigencode(r, s))
        return m

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != 'ecdsa-sha2-nistp256':
            return False
        sig = msg.get_binary()
        sigR, sigS = self._sigdecode(sig)
        signature = encode_rfc6979_signature(sigR, sigS)

        verifier = self.verifying_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
        verifier.update(data)
        try:
            verifier.verify()
        except InvalidSignature:
            return False
        else:
            return True

    def write_private_key_file(self, filename, password=None):
        key = self.signing_key or self.verifying_key
        self._write_private_key_file('EC', filename, self._to_der(key), password)

    def write_private_key(self, file_obj, password=None):
        key = self.signing_key or self.verifying_key
        self._write_private_key('EC', file_obj, self._to_der(key), password)

    @staticmethod
    def generate(curve=ec.SECP256R1(), progress_func=None):
        """
        Generate a new private RSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param function progress_func: Unused
        :returns: A new private key (`.RSAKey`) object
        """
        private_key = ec.generate_private_key(curve, backend=default_backend())
        return ECDSAKey(vals=(private_key, private_key.public_key()))

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
        s = """
-----BEGIN EC PRIVATE KEY-----
%s
-----END EC PRIVATE KEY-----
""" % "\n".join(textwrap.wrap(base64.b64encode(data).decode(), 64))
        key = serialization.load_pem_private_key(s.encode(), password=None, backend=default_backend())
        self.signing_key = key
        self.verifying_key = key.public_key()
        self.size = key.curve.key_size

    def _to_der(self, key):
        private_numbers = key.private_numbers()
        public_numbers = private_numbers.public_numbers

        private_key = deflate_long(
            private_numbers.private_value, add_sign_padding=False
        )
        x_str = deflate_long(public_numbers.x, add_sign_padding=False)
        y_str = deflate_long(public_numbers.y, add_sign_padding=False)

        key_length = key.curve.key_size // 8
        if len(x_str) < key_length:
            x_str = zero_byte * (key_length - len(x_str)) + x_str
        if len(y_str) < key_length:
            y_str = zero_byte * (key_length - len(y_str)) + y_str
        public_key = b"\x04" + x_str + y_str

        asn1_key = _ECPrivateKey()
        asn1_key.setComponentByName("version", 1)
        asn1_key.setComponentByName("privateKey", private_key)
        asn1_key.setComponentByName("parameters")
        asn1_key.getComponentByName("parameters").setComponentByName("namedCurve", _CURVE_TO_OID[type(key.curve)])
        asn1_key.setComponentByName("publicKey", "'%s'H" % binascii.hexlify(public_key))
        return encoder.encode(asn1_key)

    def _sigencode(self, r, s):
        msg = Message()
        msg.add_mpint(r)
        msg.add_mpint(s)
        return msg.asbytes()

    def _sigdecode(self, sig):
        msg = Message(sig)
        r = msg.get_mpint()
        s = msg.get_mpint()
        return r, s
