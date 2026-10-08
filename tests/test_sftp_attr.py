import struct

import pytest

from paramiko import Message, SFTPAttributes


@pytest.mark.parametrize(
    "pairs",
    [
        [(b"mime@example.com", b"text/plain")],
        [(b"first@example.com", b"same"), (b"second@example.com", b"same")],
        [(b"empty@example.com", b"")],
        [(b"binary@example.com", b"\x00\xff\x80data")],
        [
            (b"first@example.com", b"second@example.com"),
            (b"second@example.com", b"value"),
        ],
        [(b"name@example.com", b"first"), (b"name@example.com", b"last")],
        [],
    ],
)
def test_extended_attributes_wire_order(pairs):
    # SFTP v3 encodes each extension as its type followed by its data.
    packet = struct.pack(">II", SFTPAttributes.FLAG_EXTENDED, len(pairs))
    for key, value in pairs:
        for field in (key, value):
            packet += struct.pack(">I", len(field)) + field
    message = Message(packet + b"remaining packet data")

    attributes = SFTPAttributes._from_msg(message)

    assert attributes.attr == dict(pairs)
    assert message.get_remainder() == b"remaining packet data"


def test_extended_attributes_roundtrip_with_standard_fields():
    original = SFTPAttributes()
    original.st_size = 2**40
    original.st_uid = 1000
    original.st_gid = 1001
    original.st_mode = 0o100640
    original.st_atime = 1234567890
    original.st_mtime = 1234567891
    original.attr = {
        b"first@example.com": b"same",
        b"second@example.com": b"same",
        b"binary@example.com": b"\x00\xff",
    }
    message = Message()
    original._pack(message)

    restored = SFTPAttributes._from_msg(Message(message.asbytes()))

    for field in (
        "st_size",
        "st_uid",
        "st_gid",
        "st_mode",
        "st_atime",
        "st_mtime",
        "attr",
    ):
        assert getattr(restored, field) == getattr(original, field)
