#!/usr/bin/python

# standard SSH key exchange ("kex" if you wanna sound cool):
# diffie-hellman of 1024 bit key halves, using a known "p" prime and
# "g" generator.

from message import Message, inflate_long
from ssh_exception import SSHException
from transport import _MSG_NEWKEYS
from Crypto.Hash import SHA
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL

_MSG_KEXDH_INIT, _MSG_KEXDH_REPLY = range(30, 32)

# draft-ietf-secsh-transport-09.txt, page 17
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFFL
G = 2


class KexGroup1(object):

    name = 'diffie-hellman-group1-sha1'

    def __init__(self, transport):
        self.transport = transport

    def generate_x(self):
        # generate an "x" (1 < x < q), where q is (p-1)/2.
        # p is a 128-byte (1024-bit) number, where the first 64 bits are 1. 
        # therefore q can be approximated as a 2^1023.  we drop the subset of
        # potential x where the first 63 bits are 1, because some of those will be
        # larger than q (but this is a tiny tiny subset of potential x).
        while 1:
            self.transport.randpool.stir()
            x_bytes = self.transport.randpool.get_bytes(128)
            x_bytes = chr(ord(x_bytes[0]) & 0x7f) + x_bytes[1:]
            if (x_bytes[:8] != '\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF') and \
                   (x_bytes[:8] != '\x00\x00\x00\x00\x00\x00\x00\x00'):
                break
        self.x = inflate_long(x_bytes)

    def start_kex(self):
        self.generate_x()
        if self.transport.server_mode:
            # compute f = g^x mod p, but don't send it yet
            self.f = pow(G, self.x, P)
            self.transport._expect_packet(_MSG_KEXDH_INIT)
            return
        # compute e = g^x mod p (where g=2), and send it
        self.e = pow(G, self.x, P)
        m = Message()
        m.add_byte(chr(_MSG_KEXDH_INIT))
        m.add_mpint(self.e)
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEXDH_REPLY)

    def parse_next(self, ptype, m):
        if self.transport.server_mode and (ptype == _MSG_KEXDH_INIT):
            return self.parse_kexdh_init(m)
        elif not self.transport.server_mode and (ptype == _MSG_KEXDH_REPLY):
            return self.parse_kexdh_reply(m)
        raise SSHException('KexGroup1 asked to handle packet type %d' % ptype)

    def parse_kexdh_reply(self, m):
        # client mode
        host_key = m.get_string()
        self.f = m.get_mpint()
        if (self.f < 1) or (self.f > P - 1):
            raise SSHException('Server kex "f" is out of range')
        sig = m.get_string()
        K = pow(self.f, self.x, P)
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = Message().add(self.transport.local_version).add(self.transport.remote_version)
        hm.add(self.transport.local_kex_init).add(self.transport.remote_kex_init).add(host_key)
        hm.add(self.e).add(self.f).add(K)
        self.transport._set_K_H(K, SHA.new(str(hm)).digest())
        self.transport._verify_key(host_key, sig)
        self.transport._activate_outbound()

    def parse_kexdh_init(self, m):
        # server mode
        self.e = m.get_mpint()
        if (self.e < 1) or (self.e > P - 1):
            raise SSHException('Client kex "e" is out of range')
        K = pow(self.e, self.x, P)
        key = str(self.transport.get_server_key())
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = Message().add(self.transport.remote_version).add(self.transport.local_version)
        hm.add(self.transport.remote_kex_init).add(self.transport.local_kex_init).add(key)
        hm.add(self.e).add(self.f).add(K)
        H = SHA.new(str(hm)).digest()
        self.transport._set_K_H(K, H)
        # sign it
        sig = self.transport.get_server_key().sign_ssh_data(self.transport.randpool, H)
        # send reply
        m = Message()
        m.add_byte(chr(_MSG_KEXDH_REPLY))
        m.add_string(key)
        m.add_mpint(self.f)
        m.add_string(sig)
        self.transport._send_message(m)
        self.transport._activate_outbound()
