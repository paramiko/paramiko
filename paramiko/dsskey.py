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
L{DSSKey}
"""

from Crypto.PublicKey import DSA
from Crypto.Hash import SHA

from common import *
import util
from ssh_exception import SSHException
from message import Message
from ber import BER, BERException
from pkey import PKey

class DSSKey (PKey):
    """
    Representation of a DSS key which can be used to sign an verify SSH2
    data.
    """

    def __init__(self, msg=None, data=None):
        self.valid = False
        if (msg is None) and (data is not None):
            msg = Message(data)
        if (msg is None) or (msg.get_string() != 'ssh-dss'):
            return
        self.p = msg.get_mpint()
        self.q = msg.get_mpint()
        self.g = msg.get_mpint()
        self.y = msg.get_mpint()
        self.size = len(util.deflate_long(self.p, 0))
        self.valid = True

    def __str__(self):
        if not self.valid:
            return ''
        m = Message()
        m.add_string('ssh-dss')
        m.add_mpint(self.p)
        m.add_mpint(self.q)
        m.add_mpint(self.g)
        m.add_mpint(self.y)
        return str(m)

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.p)
        h = h * 37 + hash(self.q)
        h = h * 37 + hash(self.g)
        h = h * 37 + hash(self.y)
        # h might be a long by now...
        return hash(h)

    def get_name(self):
        return 'ssh-dss'

    def sign_ssh_data(self, randpool, data):
        hash = SHA.new(data).digest()
        dss = DSA.construct((long(self.y), long(self.g), long(self.p), long(self.q), long(self.x)))
        # generate a suitable k
        qsize = len(util.deflate_long(self.q, 0))
        while 1:
            k = util.inflate_long(randpool.get_bytes(qsize), 1)
            if (k > 2) and (k < self.q):
                break
        r, s = dss.sign(util.inflate_long(hash, 1), k)
        m = Message()
        m.add_string('ssh-dss')
        m.add_string(util.deflate_long(r, 0) + util.deflate_long(s, 0))
        return m

    def verify_ssh_sig(self, data, msg):
        if not self.valid:
            return 0
        if len(str(msg)) == 40:
            # spies.com bug: signature has no header
            sig = str(msg)
        else:
            kind = msg.get_string()
            if kind != 'ssh-dss':
                return 0
            sig = msg.get_string()

        # pull out (r, s) which are NOT encoded as mpints
        sigR = util.inflate_long(sig[:20], 1)
        sigS = util.inflate_long(sig[20:], 1)
        sigM = util.inflate_long(SHA.new(data).digest(), 1)

        dss = DSA.construct((long(self.y), long(self.g), long(self.p), long(self.q)))
        return dss.verify(sigM, (sigR, sigS))

    def read_private_key_file(self, filename, password=None):
        # private key file contains:
        # DSAPrivateKey = { version = 0, p, q, g, y, x }
        self.valid = False
        data = self._read_private_key_file('DSA', filename, password)
        try:
            keylist = BER(data).decode()
        except BERException, x:
            raise SSHException('Unable to parse key file: ' + str(x))
        if (type(keylist) is not list) or (len(keylist) < 6) or (keylist[0] != 0):
            raise SSHException('not a valid DSA private key file (bad ber encoding)')
        self.p = keylist[1]
        self.q = keylist[2]
        self.g = keylist[3]
        self.y = keylist[4]
        self.x = keylist[5]
        self.size = len(util.deflate_long(self.p, 0))
        self.valid = True

    def write_private_key_file(self, filename, password=None):
        if not self.valid:
            raise SSHException('Invalid key')
        keylist = [ 0, self.p, self.q, self.g, self.y, self.x ]
        try:
            b = BER()
            b.encode(keylist)
        except BERException:
            raise SSHException('Unable to create ber encoding of key')
        self._write_private_key_file('DSA', filename, str(b), password)

    def generate(bits=1024, progress_func=None):
        """
        Generate a new private DSS key.  This factory function can be used to
        generate a new host key or authentication key.

        @param bits: number of bits the generated key should be.
        @type bits: int
        @param progress_func: an optional function to call at key points in
        key generation (used by C{pyCrypto.PublicKey}).
        @type progress_func: function
        @return: new private key
        @rtype: L{DSSKey}

        @since: fearow
        """
        dsa = DSA.generate(bits, randpool.get_bytes, progress_func)
        key = DSSKey()
        key.p = dsa.p
        key.q = dsa.q
        key.g = dsa.g
        key.y = dsa.y
        key.x = dsa.x
        key.valid = True
        return key
    generate = staticmethod(generate)
