#!/usr/bin/python

# Copyright (C) 2003-2004 Robey Pointer <robey@lag.net>
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
# along with Foobar; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Useful functions used by the rest of paramiko.
"""

import sys, struct, traceback

def inflate_long(s, always_positive=0):
    "turns a normalized byte string into a long-int (adapted from Crypto.Util.number)"
    out = 0L
    negative = 0
    if not always_positive and (len(s) > 0) and (ord(s[0]) >= 0x80):
        negative = 1
    if len(s) % 4:
        filler = '\x00'
        if negative:
            filler = '\xff'
        s = filler * (4 - len(s) % 4) + s
    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack('>I', s[i:i+4])[0]
    if negative:
        out -= (1L << (8 * len(s)))
    return out

def deflate_long(n, add_sign_padding=1):
    "turns a long-int into a normalized byte string (adapted from Crypto.Util.number)"
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    while (n != 0) and (n != -1):
        s = struct.pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros, FFs
    for i in enumerate(s):
        if (n == 0) and (i[1] != '\000'):
            break
        if (n == -1) and (i[1] != '\xff'):
            break
    else:
        # degenerate case, n was either 0 or -1
        i = (0,)
        if n == 0:
            s = '\000'
        else:
            s = '\xff'
    s = s[i[0]:]
    if add_sign_padding:
        if (n == 0) and (ord(s[0]) >= 0x80):
            s = '\x00' + s
        if (n == -1) and (ord(s[0]) < 0x80):
            s = '\xff' + s
    return s

def format_binary_weird(data):
    out = ''
    for i in enumerate(data):
        out += '%02X' % ord(i[1])
        if i[0] % 2:
            out += ' '
        if i[0] % 16 == 15:
            out += '\n'
    return out

def format_binary(data, prefix=''):
    x = 0
    out = []
    while len(data) > x + 16:
        out.append(format_binary_line(data[x:x+16]))
        x += 16
    if x < len(data):
        out.append(format_binary_line(data[x:]))
    return [prefix + x for x in out]

def format_binary_line(data):
    left = ' '.join(['%02X' % ord(c) for c in data])
    right = ''.join([('.%c..' % c)[(ord(c)+61)//94] for c in data])
    return '%-50s %s' % (left, right)

def hexify(s):
    "turn a string into a hex sequence"
    return ''.join(['%02X' % ord(c) for c in s])

def safe_string(s):
    out = ''
    for c in s:
        if (ord(c) >= 32) and (ord(c) <= 127):
            out += c
        else:
            out += '%%%02X' % ord(c)
    return out

# ''.join([['%%%02X' % ord(c), c][(ord(c) >= 32) and (ord(c) <= 127)] for c in s])

def bit_length(n):
    norm = deflate_long(n, 0)
    hbyte = ord(norm[0])
    bitlen = len(norm) * 8
    while not (hbyte & 0x80):
        hbyte <<= 1
        bitlen -= 1
    return bitlen

def tb_strings():
    return ''.join(traceback.format_exception(*sys.exc_info())).split('\n')

def generate_key_bytes(hashclass, salt, key, nbytes):
    """
    Given a password, passphrase, or other human-source key, scramble it
    through a secure hash into some keyworthy bytes.  This specific algorithm
    is used for encrypting/decrypting private key files.

    @param hashclass: class from L{Crypto.Hash} that can be used as a secure
    hashing function (like C{MD5} or C{SHA}).
    @type hashclass: L{Crypto.Hash}
    @param salt: data to salt the hash with.
    @type salt: string
    @param key: human-entered password or passphrase.
    @type key: string
    @param nbytes: number of bytes to generate.
    @type nbytes: int
    @return: key data
    @rtype: string
    """
    keydata = ''
    digest = ''
    if len(salt) > 8:
        salt = salt[:8]
    while nbytes > 0:
        hash = hashclass.new()
        if len(digest) > 0:
            hash.update(digest)
        hash.update(key)
        hash.update(salt)
        digest = hash.digest()
        size = min(nbytes, len(digest))
        keydata += digest[:size]
        nbytes -= size
    return keydata
