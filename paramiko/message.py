# implementation of an SSH2 "message"

import string, types, struct
from util import inflate_long, deflate_long


class Message(object):
    "represents the encoding of an SSH2 message"

    def __init__(self, content=''):
        self.packet = content
        self.idx = 0
        self.seqno = -1

    def __str__(self):
        return self.packet

    def __repr__(self):
        return 'Message(' + repr(self.packet) + ')'
    
    def get_remainder(self):
        "remaining bytes still unparsed"
        return self.packet[self.idx:]

    def get_so_far(self):
        "bytes that have been parsed"
        return self.packet[:self.idx]

    def get_bytes(self, n):
        if self.idx + n > len(self.packet):
            return '\x00'*n
        b = self.packet[self.idx:self.idx+n]
        self.idx = self.idx + n
        return b
    
    def get_byte(self):
        return self.get_bytes(1)

    def get_boolean(self):
        b = self.get_bytes(1)
        if b == '\x00':
            return 0
        else:
            return 1

    def get_int(self):
        x = self.packet
        i = self.idx
        if i + 4 > len(x):
            return 0
        n = struct.unpack('>I', x[i:i+4])[0]
        self.idx = i+4
        return n

    def get_mpint(self):
        return inflate_long(self.get_string())

    def get_string(self):
        l = self.get_int()
        if self.idx + l > len(self.packet):
            return ''
        str = self.packet[self.idx:self.idx+l]
        self.idx = self.idx + l
        return str

    def get_list(self):
        str = self.get_string()
        l = string.split(str, ',')
        return l

    def add_bytes(self, b):
        self.packet = self.packet + b
        return self

    def add_byte(self, b):
        self.packet = self.packet + b
        return self

    def add_boolean(self, b):
        if b:
            self.add_byte('\x01')
        else:
            self.add_byte('\x00')
        return self
            
    def add_int(self, n):
        self.packet = self.packet + struct.pack('>I', n)
        return self

    def add_mpint(self, z):
        "this only works on positive numbers"
        self.add_string(deflate_long(z))
        return self

    def add_string(self, s):
        self.add_int(len(s))
        self.packet = self.packet + s
        return self

    def add_list(self, l):
        out = string.join(l, ',')
        self.add_int(len(out))
        self.packet = self.packet + out
        return self
        
    def add(self, i):
        if type(i) == types.StringType:
            return self.add_string(i)
        elif type(i) == types.IntType:
            return self.add_int(i)
        elif type(i) == types.LongType:
            if i > 0xffffffffL:
                return self.add_mpint(i)
            else:
                return self.add_int(i)
        elif type(i) == types.ListType:
            return self.add_list(i)
        else:
            raise exception('Unknown type')
