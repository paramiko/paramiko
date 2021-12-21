import base64
import sys
import time

__all__ = [
    "BytesIO",
    "MAXSIZE",
    "PY2",
    "StringIO",
    "b",
    "b2s",
    "builtins",
    "byte_chr",
    "byte_mask",
    "byte_ord",
    "bytes",
    "bytes_types",
    "decodebytes",
    "encodebytes",
    "input",
    "integer_types",
    "is_callable",
    "long",
    "next",
    "string_types",
    "text_type",
    "u",
]

PY2 = False

import collections
import struct
import builtins

string_types = str
text_type = str
bytes = bytes
bytes_types = bytes
integer_types = int


class long(int):
    pass


input = input
decodebytes = base64.decodebytes
encodebytes = base64.encodebytes


def byte_ord(c):
    # In case we're handed a string instead of an int.
    if not isinstance(c, int):
        c = ord(c)
    return c


def byte_chr(c):
    assert isinstance(c, int)
    return struct.pack("B", c)


def byte_mask(c, mask):
    assert isinstance(c, int)
    return struct.pack("B", c & mask)


def b(s, encoding="utf8"):
    """cast unicode or bytes to bytes"""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode(encoding)
    else:
        raise TypeError("Expected unicode or bytes, got {!r}".format(s))


def u(s, encoding="utf8"):
    """cast bytes or unicode to unicode"""
    if isinstance(s, bytes):
        return s.decode(encoding)
    elif isinstance(s, str):
        return s
    else:
        raise TypeError("Expected unicode or bytes, got {!r}".format(s))


def b2s(s):
    return s.decode() if isinstance(s, bytes) else s


import io

StringIO = io.StringIO  # NOQA
BytesIO = io.BytesIO  # NOQA


def is_callable(c):
    return isinstance(c, collections.Callable)


def get_next(c):
    return c.__next__


next = next

MAXSIZE = sys.maxsize  # NOQA

strftime = time.strftime  # NOQA
