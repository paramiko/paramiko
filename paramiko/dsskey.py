#!/usr/bin/python

import base64
from ssh_exception import SSHException
from message import Message
from transport import _MSG_USERAUTH_REQUEST
from util import inflate_long, deflate_long
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
from ber import BER
from pkey import PKey

from util import format_binary

class DSSKey (PKey):

    def __init__(self, msg=None):
        self.valid = 0
        if (msg == None) or (msg.get_string() != 'ssh-dss'):
            return
        self.p = msg.get_mpint()
        self.q = msg.get_mpint()
        self.g = msg.get_mpint()
        self.y = msg.get_mpint()
        self.size = len(deflate_long(self.p, 0))
        self.valid = 1

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

    def get_name(self):
        return 'ssh-dss'

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
        sigR = inflate_long(sig[:20], 1)
        sigS = inflate_long(sig[20:], 1)
        sigM = inflate_long(SHA.new(data).digest(), 1)

        dss = DSA.construct((long(self.y), long(self.g), long(self.p), long(self.q)))
        return dss.verify(sigM, (sigR, sigS))

    def sign_ssh_data(self, randpool, data):
        hash = SHA.new(data).digest()
        dss = DSA.construct((long(self.y), long(self.g), long(self.p), long(self.q), long(self.x)))
        # generate a suitable k
        qsize = len(deflate_long(self.q, 0))
        while 1:
            k = inflate_long(randpool.get_bytes(qsize), 1)
            if (k > 2) and (k < self.q):
                break
        r, s = dss.sign(inflate_long(hash, 1), k)
        m = Message()
        m.add_string('ssh-dss')
        m.add_string(deflate_long(r, 0) + deflate_long(s, 0))
        return str(m)

    def read_private_key_file(self, filename):
        # private key file contains:
        # DSAPrivateKey = { version = 0, p, q, g, y, x }
        self.valid = 0
        f = open(filename, 'r')
        lines = f.readlines()
        f.close()
        if lines[0].strip() != '-----BEGIN DSA PRIVATE KEY-----':
            raise SSHException('not a valid DSA private key file')
        data = base64.decodestring(''.join(lines[1:-1]))
        keylist = BER(data).decode()
        if (type(keylist) != type([])) or (len(keylist) < 6) or (keylist[0] != 0):
            raise SSHException('not a valid DSA private key file (bad ber encoding)')
        self.p = keylist[1]
        self.q = keylist[2]
        self.g = keylist[3]
        self.y = keylist[4]
        self.x = keylist[5]
        self.size = len(deflate_long(self.p, 0))
        self.valid = 1

    def sign_ssh_session(self, randpool, sid, username):
        m = Message()
        m.add_string(sid)
        m.add_byte(chr(_MSG_USERAUTH_REQUEST))
        m.add_string(username)
        m.add_string('ssh-connection')
        m.add_string('publickey')
        m.add_boolean(1)
        m.add_string('ssh-dss')
        m.add_string(str(self))
        return self.sign_ssh_data(randpool, str(m))
