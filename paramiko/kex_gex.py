#!/usr/bin/python

# variant on group1 (see kex_group1.py) where the prime "p" and generator "g"
# are provided by the server.  a bit more work is required on our side (and a
# LOT more on the server side).

from message import Message
from util import inflate_long, deflate_long, bit_length
from ssh_exception import SSHException
from transport import _MSG_NEWKEYS
from Crypto.Hash import SHA
from Crypto.Util import number
from logging import DEBUG

_MSG_KEXDH_GEX_GROUP, _MSG_KEXDH_GEX_INIT, _MSG_KEXDH_GEX_REPLY, _MSG_KEXDH_GEX_REQUEST = range(31, 35)


class KexGex(object):

    name = 'diffie-hellman-group-exchange-sha1'
    min_bits = 1024
    max_bits = 8192
    preferred_bits = 2048

    def __init__(self, transport):
        self.transport = transport

    def start_kex(self):
        if self.transport.server_mode:
            self.transport._expect_packet(_MSG_KEXDH_GEX_REQUEST)
            return
        # request a bit range: we accept (min_bits) to (max_bits), but prefer
        # (preferred_bits).  according to the spec, we shouldn't pull the
        # minimum up above 1024.
        m = Message()
        m.add_byte(chr(_MSG_KEXDH_GEX_REQUEST))
        m.add_int(self.min_bits)
        m.add_int(self.preferred_bits)
        m.add_int(self.max_bits)
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEXDH_GEX_GROUP)

    def parse_next(self, ptype, m):
        if ptype == _MSG_KEXDH_GEX_REQUEST:
            return self._parse_kexdh_gex_request(m)
        elif ptype == _MSG_KEXDH_GEX_GROUP:
            return self._parse_kexdh_gex_group(m)
        elif ptype == _MSG_KEXDH_GEX_INIT:
            return self._parse_kexdh_gex_init(m)
        elif ptype == _MSG_KEXDH_GEX_REPLY:
            return self._parse_kexdh_gex_reply(m)
        raise SSHException('KexGex asked to handle packet type %d' % ptype)

    def _generate_x(self):
        # generate an "x" (1 < x < (p-1)/2).
        q = (self.p - 1) // 2
        qnorm = deflate_long(q, 0)
        qhbyte = ord(qnorm[0])
        bytes = len(qnorm)
        qmask = 0xff
        while not (qhbyte & 0x80):
            qhbyte <<= 1
            qmask >>= 1
        while 1:
            self.transport.randpool.stir()
            x_bytes = self.transport.randpool.get_bytes(bytes)
            x_bytes = chr(ord(x_bytes[0]) & qmask) + x_bytes[1:]
            x = inflate_long(x_bytes, 1)
            if (x > 1) and (x < q):
                break
        self.x = x

    def _parse_kexdh_gex_request(self, m):
        min = m.get_int()
        preferred = m.get_int()
        max = m.get_int()
        # smoosh the user's preferred size into our own limits
        if preferred > self.max_bits:
            preferred = self.max_bits
        if preferred < self.min_bits:
            preferred = self.min_bits
        # fix min/max if they're inconsistent.  technically, we could just pout
        # and hang up, but there's no harm in giving them the benefit of the
        # doubt and just picking a bitsize for them.
        if min > preferred:
            min = preferred
        if max < preferred:
            max = preferred
        # now save a copy
        self.min_bits = min
        self.preferred_bits = preferred
        self.max_bits = max
        # generate prime
        pack = self.transport._get_modulus_pack()
        if pack is None:
            raise SSHException('Can\'t do server-side gex with no modulus pack')
        self.g, self.p = pack.get_modulus(min, preferred, max)
        m = Message()
        m.add_byte(chr(_MSG_KEXDH_GEX_GROUP))
        m.add_mpint(self.p)
        m.add_mpint(self.g)
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEXDH_GEX_INIT)

    def _parse_kexdh_gex_group(self, m):
        self.p = m.get_mpint()
        self.g = m.get_mpint()
        # reject if p's bit length < 1024 or > 8192
        bitlen = bit_length(self.p)
        if (bitlen < 1024) or (bitlen > 8192):
            raise SSHException('Server-generated gex p (don\'t ask) is out of range (%d bits)' % bitlen)
        self.transport._log(DEBUG, 'Got server p (%d bits)' % bitlen)
        self._generate_x()
        # now compute e = g^x mod p
        self.e = pow(self.g, self.x, self.p)
        m = Message()
        m.add_byte(chr(_MSG_KEXDH_GEX_INIT))
        m.add_mpint(self.e)
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEXDH_GEX_REPLY)

    def _parse_kexdh_gex_init(self, m):
        self.e = m.get_mpint()
        if (self.e < 1) or (self.e > self.p - 1):
            raise SSHException('Client kex "e" is out of range')
        self._generate_x()
        self.f = pow(self.g, self.x, self.p)
        K = pow(self.e, self.x, self.p)
        key = str(self.transport.get_server_key())
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K)
        hm = Message().add(self.transport.remote_version).add(self.transport.local_version)
        hm.add(self.transport.remote_kex_init).add(self.transport.local_kex_init).add(key)
        hm.add_int(self.min_bits)
        hm.add_int(self.preferred_bits)
        hm.add_int(self.max_bits)
        hm.add_mpint(self.p)
        hm.add_mpint(self.g)
        hm.add(self.e).add(self.f).add(K)
        H = SHA.new(str(hm)).digest()
        self.transport._set_K_H(K, H)
        # sign it
        sig = self.transport.get_server_key().sign_ssh_data(self.transport.randpool, H)
        # send reply
        m = Message()
        m.add_byte(chr(_MSG_KEXDH_GEX_REPLY))
        m.add_string(key)
        m.add_mpint(self.f)
        m.add_string(sig)
        self.transport._send_message(m)
        self.transport._activate_outbound()
        
    def _parse_kexdh_gex_reply(self, m):
        host_key = m.get_string()
        self.f = m.get_mpint()
        sig = m.get_string()
        if (self.f < 1) or (self.f > self.p - 1):
            raise SSHException('Server kex "f" is out of range')
        K = pow(self.f, self.x, self.p)
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K)
        hm = Message().add(self.transport.local_version).add(self.transport.remote_version)
        hm.add(self.transport.local_kex_init).add(self.transport.remote_kex_init).add(host_key)
        hm.add_int(self.min_bits)
        hm.add_int(self.preferred_bits)
        hm.add_int(self.max_bits)
        hm.add_mpint(self.p)
        hm.add_mpint(self.g)
        hm.add(self.e).add(self.f).add(K)
        self.transport._set_K_H(K, SHA.new(str(hm)).digest())
        self.transport._verify_key(host_key, sig)
        self.transport._activate_outbound()


    
