import sys

__all__ = ['PY3', 'string_types', 'integer_types', 'text_type', 'bytes_type', 'long', 'input', 'bytestring', 'byte_ord', 'byte_chr', 'byte_mask', 'b', 'u', 'StringIO', 'BytesIO', 'is_callable', 'MAXSIZE', 'next']

PY3 = sys.version_info[0] >= 3

if PY3:
    import collections
    import struct
    string_types = str
    integer_types = int
    text_type = str
    bytes_type = bytes
    long = int
    input = input

    def bytestring(s):
        return s

    def byte_ord(c):
        assert isinstance(c, int)
        return c

    def byte_chr(c):
        assert isinstance(c, int)
        return struct.pack('B', c)

    def byte_mask(c, mask):
        assert isinstance(c, int)
        return struct.pack('B', c & mask)

    def b(s, encoding='utf8'):
        """cast unicode or bytes to bytes"""
        if isinstance(s, bytes):
            return s
        elif isinstance(s, str):
            return s.encode(encoding)
        else:
            raise TypeError("Expected unicode or bytes, got %r" % s)

    def u(s, encoding='utf8'):
        """cast bytes or unicode to unicode"""
        if isinstance(s, bytes):
            return s.decode(encoding)
        elif isinstance(s, str):
            return s
        else:
            raise TypeError("Expected unicode or bytes, got %r" % s)

    import io
    StringIO = io.StringIO      # NOQA
    BytesIO = io.BytesIO        # NOQA

    def is_callable(c):
        return isinstance(c, collections.Callable)

    def get_next(c):
        return c.__next__

    next = next

    MAXSIZE = sys.maxsize       # NOQA
else:
    string_types = basestring
    integer_types = (int, long)
    text_type = unicode
    bytes_type = str
    long = long
    input = raw_input

    def bytestring(s):  # NOQA
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return s

    byte_ord = ord  # NOQA
    byte_chr = chr  # NOQA

    def byte_mask(c, mask):
        return chr(ord(c) & mask)

    def b(s, encoding='utf8'):  # NOQA
        """cast unicode or bytes to bytes"""
        if isinstance(s, str):
            return s
        elif isinstance(s, unicode):
            return s.encode(encoding)
        else:
            raise TypeError("Expected unicode or bytes, got %r" % s)

    def u(s, encoding='utf8'):  # NOQA
        """cast bytes or unicode to unicode"""
        if isinstance(s, str):
            return s.decode(encoding)
        elif isinstance(s, unicode):
            return s
        else:
            raise TypeError("Expected unicode or bytes, got %r" % s)

    try:
        import cStringIO
        StringIO = cStringIO.StringIO   # NOQA
    except ImportError:
        import StringIO
        StringIO = StringIO.StringIO    # NOQA

    BytesIO = StringIO

    def is_callable(c):  # NOQA
        return callable(c)

    def get_next(c):  # NOQA
        return c.next

    def next(c):
        return c.next()

    # It's possible to have sizeof(long) != sizeof(Py_ssize_t).
    class X(object):
        def __len__(self):
            return 1 << 31
    try:
        len(X())
    except OverflowError:
        # 32-bit
        MAXSIZE = int((1 << 31) - 1)        # NOQA
    else:
        # 64-bit
        MAXSIZE = int((1 << 63) - 1)        # NOQA
    del X
