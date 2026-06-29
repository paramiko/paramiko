# Copyright (C) 2024  Paramiko developers
#
# This file is part of Paramiko.
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
Tests for :mod:`paramiko.ber` -- BER (Basic Encoding Rules) encode/decode.
"""

import pytest

from paramiko.ber import BER, BERException
from paramiko.sftp import int64


class TestBERDecode:
    """Tests for BER.decode_next and BER.decode."""

    def test_decode_empty_returns_none(self):
        """Decoding an empty byte string should return None."""
        assert BER(b"").decode() is None

    def test_decode_integer_zero(self):
        ber = BER()
        ber.encode(0)
        assert BER(ber.asbytes()).decode() == 0

    def test_decode_integer_positive(self):
        ber = BER()
        ber.encode(42)
        assert BER(ber.asbytes()).decode() == 42

    def test_decode_integer_large(self):
        """Integers larger than 127 bytes trigger the multi-byte length path."""
        big = 2**128
        ber = BER()
        ber.encode(big)
        assert BER(ber.asbytes()).decode() == big

    def test_decode_sequence_integers(self):
        ber = BER()
        ber.encode([1, 2, 3])
        result = BER(ber.asbytes()).decode()
        assert result == [1, 2, 3]

    def test_decode_sequence_empty(self):
        ber = BER()
        ber.encode([])
        result = BER(ber.asbytes()).decode()
        assert result == []

    def test_decode_nested_sequence(self):
        ber = BER()
        ber.encode([1, [2, 3], 4])
        result = BER(ber.asbytes()).decode()
        assert result == [1, [2, 3], 4]

    def test_decode_truncated_returns_none(self):
        """Truncated data that cannot fit the declared length returns None."""
        valid = b"\x02\x01\x2a"
        assert BER(valid[:-1]).decode() is None

    def test_decode_unknown_ident_raises(self):
        """An unrecognised BER tag should raise BERException."""
        raw = b"\x05\x00"
        with pytest.raises(BERException):
            BER(raw).decode()


class TestBEREncode:
    """Tests for BER.encode and BER.encode_tlv."""

    def test_encode_bool_true(self):
        ber = BER()
        ber.encode(True)
        assert ber.asbytes() == b"\x01\x01\xff"

    def test_encode_bool_false(self):
        ber = BER()
        ber.encode(False)
        assert ber.asbytes() == b"\x01\x01\x00"

    def test_encode_unknown_type_raises(self):
        ber = BER()
        with pytest.raises(BERException):
            ber.encode({"key": "value"})

    def test_encode_unknown_type_raises_for_float(self):
        ber = BER()
        with pytest.raises(BERException):
            ber.encode(3.14)

    def test_encode_int64(self):
        """int64 values should be treated identically to int."""
        val = int64(99)
        ber = BER()
        ber.encode(val)
        result = BER(ber.asbytes()).decode()
        assert result == 99

    def test_encode_tuple_same_as_list(self):
        """Tuples should be encoded as BER sequences, same as lists."""
        ber_list = BER()
        ber_list.encode([10, 20])
        ber_tuple = BER()
        ber_tuple.encode((10, 20))
        assert ber_list.asbytes() == ber_tuple.asbytes()


class TestBERRoundTrip:
    """Encode then decode should be an identity operation."""

    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 65535, 2**64])
    def test_integer_roundtrip(self, value):
        ber = BER()
        ber.encode(value)
        assert BER(ber.asbytes()).decode() == value

    @pytest.mark.parametrize(
        "seq",
        [
            [1],
            [1, 2, 3],
            [0, 255, 65535],
            [[1, 2], [3, 4]],
        ],
    )
    def test_sequence_roundtrip(self, seq):
        ber = BER()
        ber.encode(seq)
        assert BER(ber.asbytes()).decode() == seq


class TestBERRepr:
    def test_repr(self):
        ber = BER(b"\x01\x02")
        assert "BER(" in repr(ber)

    def test_asbytes(self):
        data = b"\x01\x01\xff"
        ber = BER(data)
        assert ber.asbytes() == data
