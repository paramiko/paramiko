#!/usr/bin/python

import struct

def inflate_long(s, always_positive=0):
    "turns a normalized byte string into a long-int (adapted from Crypto.Util.number)"
    out = 0L
    if len(s) % 4:
        filler = '\x00'
        if not always_positive and (ord(s[0]) >= 0x80):
            # negative
            filler = '\xff'
        s = filler * (4 - len(s) % 4) + s
    # FIXME: this doesn't actually handle negative.
    # luckily ssh never uses negative bignums.
    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack('>I', s[i:i+4])[0]
    return out

def deflate_long(n, add_sign_padding=1):
    "turns a long-int into a normalized byte string (adapted from Crypto.Util.number)"
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    while n > 0:
        s = struct.pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in enumerate(s):
        if i[1] != '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = (0,)
    s = s[i[0]:]
    if (ord(s[0]) >= 0x80) and add_sign_padding:
        s = '\x00' + s
    return s


class BER(object):

    def __init__(self, content=''):
        self.content = content
        self.idx = 0

    def __str__(self):
        return self.content

    def __repr__(self):
        return 'BER(' + repr(self.content) + ')'

    def decode(self):
        return self.decode_next()
    
    def decode_next(self):
        if self.idx >= len(self.content):
            return None
        id = ord(self.content[self.idx])
        self.idx += 1
        if (id & 31) == 31:
            # identifier > 30
            id = 0
            while self.idx < len(self.content):
                t = ord(self.content[self.idx])
                if not (t & 0x80):
                    break
                id = (id << 7) | (t & 0x7f)
                self.idx += 1
        if self.idx >= len(self.content):
            return None
        # now fetch length
        size = ord(self.content[self.idx])
        self.idx += 1
        if size & 0x80:
            # more complimicated...
            # FIXME: theoretically should handle indefinite-length (0x80)
            t = size & 0x7f
            if self.idx + t > len(self.content):
                return None
            size = 0
            while t > 0:
                size = (size << 8) | ord(self.content[self.idx])
                self.idx += 1
                t -= 1
        if self.idx + size > len(self.content):
            # can't fit
            return None
        data = self.content[self.idx : self.idx + size]
        self.idx += size
        # now switch on id
        if id == 0x30:
            # sequence
            return self.decode_sequence(data)
        elif id == 2:
            # int
            return inflate_long(data)
        else:
            # 1: boolean (00 false, otherwise true)
            raise Exception('Unknown ber encoding type %d (robey is lazy)' % id)

    def decode_sequence(data):
        out = []
        b = BER(data)
        while 1:
            x = b.decode_next()
            if x == None:
                return out
            out.append(x)
    decode_sequence = staticmethod(decode_sequence)

