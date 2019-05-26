import sys
import base64

__all__ = [
    "PY2",
    "StringIO",
    "b",
    "builtins",
    "byte_chr",
    "byte_mask",
    "byte_ord",
    "decodebytes",
    "encodebytes",
    "input",
    "integer_types",
    "long",
    "string_types",
    "text_type",
    "u",
]

PY2 = sys.version_info[0] < 3

if PY2:
    string_types = basestring  # NOQA
    text_type = unicode  # NOQA
    integer_types = (int, long)  # NOQA
    long = long  # NOQA
    input = raw_input  # NOQA
    decodebytes = base64.decodestring
    encodebytes = base64.encodestring

    import __builtin__ as builtins

    byte_ord = ord  # NOQA
    byte_chr = chr  # NOQA

    def byte_mask(c, mask):
        return chr(ord(c) & mask)

    def b(s):
        """cast unicode or bytes to bytes"""
        if isinstance(s, (str, buffer)):  # noqa: F821
            return s
        elif isinstance(s, unicode):  # NOQA
            return s.encode('utf-8')
        else:
            raise TypeError("Expected unicode or bytes, got {!r}".format(s))

    def u(s):
        """cast bytes or unicode to unicode"""
        if isinstance(s, unicode):  # NOQA
            return s
        elif isinstance(s, (str, buffer)):  # noqa: F821
            return s.decode('utf-8')
        else:
            raise TypeError("Expected unicode or bytes, got {!r}".format(s))

    import cStringIO
    StringIO = cStringIO.StringIO


else:  # python 3+
    import struct
    import builtins
    string_types = str
    text_type = str
    integer_types = int
    input = input
    decodebytes = base64.decodebytes
    encodebytes = base64.encodebytes

    class long(int):
        pass

    def byte_ord(c):
        # In case we're handed a string instead of an int.
        if not isinstance(c, int):
            c = ord(c)
        return c

    def byte_chr(c):
        assert isinstance(c, int)
        return struct.pack('B', c)

    def byte_mask(c, mask):
        assert isinstance(c, int)
        return struct.pack('B', c & mask)

    def b(s):
        """cast unicode or bytes to bytes"""
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode('utf-8')
        else:
            raise TypeError("Expected unicode or bytes, got {!r}".format(s))

    def u(s):
        """cast bytes or unicode to unicode"""
        if isinstance(s, bytes):
            return s.decode('utf-8')
        elif isinstance(s, str):
            return s
        else:
            raise TypeError("Expected unicode or bytes, got {!r}".format(s))

    import io
    StringIO = io.StringIO
