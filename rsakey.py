#!/usr/bin/python

from message import Message
from transport import MSG_USERAUTH_REQUEST
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from ber import BER
from util import format_binary, inflate_long, deflate_long
import base64

class RSAKey(object):

    def __init__(self, msg=None):
        self.valid = 0
        if (msg == None) or (msg.get_string() != 'ssh-rsa'):
            return
        self.e = msg.get_mpint()
        self.n = msg.get_mpint()
        self.size = len(deflate_long(self.n, 0))
        self.valid = 1

    def __str__(self):
        if not self.valid:
            return ''
        m = Message()
        m.add_string('ssh-rsa')
        m.add_mpint(self.e)
        m.add_mpint(self.n)
        return str(m)

    def get_name(self):
        return 'ssh-rsa'

    def get_fingerprint(self):
        return MD5.new(str(self)).digest()

    def pkcs1imify(self, data):
        """
        turn a 20-byte SHA1 hash into a blob of data as large as the key's N,
        using PKCS1's \"emsa-pkcs1-v1_5\" encoding.  totally bizarre.
        """
        SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
        filler = '\xff' * (self.size - len(SHA1_DIGESTINFO) - len(data) - 3)
        return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + data

    def verify_ssh_sig(self, data, msg):
        if (not self.valid) or (msg.get_string() != 'ssh-rsa'):
            return 0
        sig = inflate_long(msg.get_string(), 1)
        # verify the signature by SHA'ing the data and encrypting it using the
        # public key.  some wackiness ensues where we "pkcs1imify" the 20-byte
        # hash into a string as long as the RSA key.
        hash = inflate_long(self.pkcs1imify(SHA.new(data).digest()), 1)
        rsa = RSA.construct((long(self.n), long(self.e)))
        return rsa.verify(hash, (sig,))

    def sign_ssh_data(self, randpool, data):
        hash = SHA.new(data).digest()
        rsa = RSA.construct((long(self.n), long(self.e), long(self.d)))
        sig = deflate_long(rsa.sign(self.pkcs1imify(hash), '')[0], 0)
        m = Message()
        m.add_string('ssh-rsa')
        m.add_string(sig)
        return str(m)

    def read_private_key_file(self, filename):
        "throws a file exception, or SSHException (on invalid key), or base64 decoding exception"
        # private key file contains:
        # RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
        self.valid = 0
        f = open(filename, 'r')
        lines = f.readlines()
        f.close()
        if lines[0].strip() != '-----BEGIN RSA PRIVATE KEY-----':
            raise SSHException('not a valid DSA private key file')
        data = base64.decodestring(''.join(lines[1:-1]))
        keylist = BER(data).decode()
        if (type(keylist) != type([])) or (len(keylist) < 4) or (keylist[0] != 0):
            raise SSHException('not a valid DSA private key file (bad ber encoding)')
        self.n = keylist[1]
        self.e = keylist[2]
        self.d = keylist[3]
        # not really needed
        self.p = keylist[4]
        self.q = keylist[5]
        self.size = len(deflate_long(self.n, 0))
        self.valid = 1

    def sign_ssh_session(self, randpool, sid, username):
        m = Message()
        m.add_string(sid)
        m.add_byte(chr(MSG_USERAUTH_REQUEST))
        m.add_string(username)
        m.add_string('ssh-connection')
        m.add_string('publickey')
        m.add_boolean(1)
        m.add_string('ssh-rsa')
        m.add_string(str(self))
        return self.sign_ssh_data(randpool, str(m))

