#!/usr/bin/python

MSG_DISCONNECT, MSG_IGNORE, MSG_UNIMPLEMENTED, MSG_DEBUG, MSG_SERVICE_REQUEST, \
	MSG_SERVICE_ACCEPT = range(1, 7)
MSG_KEXINIT, MSG_NEWKEYS = range(20, 22)
MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE, MSG_USERAUTH_SUCCESS, \
        MSG_USERAUTH_BANNER = range(50, 54)
MSG_USERAUTH_PK_OK = 60
MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_SUCCESS, MSG_CHANNEL_OPEN_FAILURE, \
	MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA, \
	MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE, MSG_CHANNEL_REQUEST, \
	MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE = range(90, 101)

import sys, os, string, threading, socket, logging, struct
from message import Message
from channel import Channel
from paramiko import SSHException
from util import format_binary, safe_string, inflate_long, deflate_long, tb_strings
from rsakey import RSAKey
from dsskey import DSSKey
from kex_group1 import KexGroup1
from kex_gex import KexGex

# these come from PyCrypt
#     http://www.amk.ca/python/writing/pycrypt/
# i believe this on the standards track.
# PyCrypt compiled for Win32 can be downloaded from the HashTar homepage:
#     http://nitace.bsd.uchicago.edu:8080/hashtar
from Crypto.Util.randpool import PersistentRandomPool, RandomPool
from Crypto.Cipher import Blowfish, AES, DES3
from Crypto.Hash import SHA, MD5, HMAC
from Crypto.PublicKey import RSA

from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL


# channel request failed reasons:
CONNECTION_FAILED_CODE = {
    1: 'Administratively prohibited',
    2: 'Connect failed',
    3: 'Unknown channel type',
    4: 'Resource shortage'
}


# keep a crypto-strong PRNG nearby
try:
    randpool = PersistentRandomPool(os.getenv('HOME') + '/.randpool')
except:
    # the above will likely fail on Windows - fall back to non-persistent random pool
    randpool = RandomPool()

randpool.randomize()


class BaseTransport(threading.Thread):
    '''
    An SSH Transport attaches to a stream (usually a socket), negotiates an
    encrypted session, authenticates, and then creates stream tunnels, called
    "channels", across the session.  Multiple channels can be multiplexed
    across a single session (and often are, in the case of port forwardings).

    Transport expects to receive a "socket-like object" to talk to the SSH
    server.  This means it has a method "settimeout" which sets a timeout for
    read/write calls, and a method "send()" to write bytes and "recv()" to
    read bytes.  "recv" returns from 1 to n bytes, or 0 if the stream has been
    closed.  EOFError may also be raised on a closed stream.  (A return value
    of 0 is converted to an EOFError internally.)  "send(s)" writes from 1 to
    len(s) bytes, and returns the number of bytes written, or returns 0 if the
    stream has been closed.  As with instream, EOFError may be raised instead
    of returning 0.

    FIXME: Describe events here.
    '''

    PROTO_ID = '2.0'
    CLIENT_ID = 'pyssh_1.1'

    preferred_ciphers = [ 'aes128-cbc', 'blowfish-cbc', 'aes256-cbc', '3des-cbc' ]
    preferred_macs = [ 'hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96' ]
    preferred_keys = [ 'ssh-rsa', 'ssh-dss' ]
    preferred_kex = [ 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1' ]

    cipher_info = {
        'blowfish-cbc': { 'class': Blowfish, 'mode': Blowfish.MODE_CBC, 'block-size': 8, 'key-size': 16 },
        'aes128-cbc': { 'class': AES, 'mode': AES.MODE_CBC, 'block-size': 16, 'key-size': 16 },
        'aes256-cbc': { 'class': AES, 'mode': AES.MODE_CBC, 'block-size': 16, 'key-size': 32 },
        '3des-cbc': { 'class': DES3, 'mode': DES3.MODE_CBC, 'block-size': 8, 'key-size': 24 },
        }

    mac_info = {
        'hmac-sha1': { 'class': SHA, 'size': 20 },
        'hmac-sha1-96': { 'class': SHA, 'size': 12 },
        'hmac-md5': { 'class': MD5, 'size': 16 },
        'hmac-md5-96': { 'class': MD5, 'size': 12 },
        }

    kex_info = {
        'diffie-hellman-group1-sha1': KexGroup1,
        'diffie-hellman-group-exchange-sha1': KexGex,
        }

    REKEY_PACKETS = pow(2, 30)
    REKEY_BYTES = pow(2, 30)

    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_FAILED_CONNECT_FAILED, OPEN_FAILED_UNKNOWN_CHANNEL_TYPE, \
	OPEN_FAILED_RESOURCE_SHORTAGE = range(1, 5)

    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.randpool = randpool
        self.sock = sock
        self.sock.settimeout(0.1)
        # negotiated crypto parameters
        self.local_version = 'SSH-' + self.PROTO_ID + '-' + self.CLIENT_ID
        self.remote_version = ''
        self.block_size_out = self.block_size_in = 8
        self.local_mac_len = self.remote_mac_len = 0
        self.engine_in = self.engine_out = None
        self.local_cipher = self.remote_cipher = ''
        self.sequence_number_in = self.sequence_number_out = 0L
        self.local_kex_init = self.remote_kex_init = None
        self.session_id = None
        # /negotiated crypto parameters
        self.expected_packet = 0
        self.active = 0
        self.initial_kex_done = 0
        self.write_lock = threading.Lock()	# lock around outbound writes (packet computation)
        self.lock = threading.Lock()		# synchronization (always higher level than write_lock)
        self.authenticated = 0
        self.channels = { }			# (id -> Channel)
        self.channel_events = { }		# (id -> Event)
        self.channel_counter = 1
        self.logger = logging.getLogger('paramiko.transport')
        self.window_size = 65536
        self.max_packet_size = 2048
        self.ultra_debug = 0
        # used for noticing when to re-key:
        self.received_bytes = 0
        self.received_packets = 0
        self.received_packets_overflow = 0
        # user-defined event callbacks:
        self.completion_event = None
        # server mode:
        self.server_mode = 0
        self.server_key_dict = { }
        self.server_accepts = [ ]
        self.server_accept_cv = threading.Condition(self.lock)

    def start_client(self, event=None):
        self.completion_event = event
        self.start()

    def start_server(self, event=None):
        self.server_mode = 1
        self.completion_event = event
        self.start()

    def add_server_key(self, key):
        self.server_key_dict[key.get_name()] = key

    def get_server_key(self):
        try:
            return self.server_key_dict[self.host_key_type]
        except KeyError:
            return None

    def __repr__(self):
        if not self.active:
            return '<paramiko.Transport (unconnected)>'
        out = '<sesch.Transport'
        #if self.remote_version != '':
        #    out += ' (server version "%s")' % self.remote_version
        if self.local_cipher != '':
            out += ' (cipher %s)' % self.local_cipher
        if self.authenticated:
            if len(self.channels) == 1:
                out += ' (active; 1 open channel)'
            else:
                out += ' (active; %d open channels)' % len(self.channels)
        elif self.initial_kex_done:
            out += ' (connected; awaiting auth)'
        else:
            out += ' (connecting)'
        out += '>'
        return out

    def log(self, level, msg):
        if type(msg) == type([]):
            for m in msg:
                self.logger.log(level, m)
        else:
            self.logger.log(level, msg)

    def close(self):
        self.active = 0
        self.engine_in = self.engine_out = None
        self.sequence_number_in = self.sequence_number_out = 0L
        for chan in self.channels.values():
            chan.unlink()

    def get_remote_server_key(self):
        'returns (type, key) where type is like "ssh-rsa" and key is an opaque string'
        if (not self.active) or (not self.initial_kex_done):
            raise SSHException('No existing session')
        key_msg = Message(self.host_key)
        key_type = key_msg.get_string()
        return key_type, self.host_key

    def is_active(self):
        return self.active

    def is_authenticated(self):
        return self.authenticated and self.active

    def open_session(self):
        return self.open_channel('session')

    def open_channel(self, kind):
        chan = None
        try:
            self.lock.acquire()
            chanid = self.channel_counter
            self.channel_counter += 1
            m = Message()
            m.add_byte(chr(MSG_CHANNEL_OPEN))
            m.add_string(kind)
            m.add_int(chanid)
            m.add_int(self.window_size)
            m.add_int(self.max_packet_size)
            self.channels[chanid] = chan = Channel(chanid)
            self.channel_events[chanid] = event = threading.Event()
            chan.set_transport(self)
            chan.set_window(self.window_size, self.max_packet_size)
            self.send_message(m)
        finally:
            self.lock.release()
        while 1:
            event.wait(0.1);
            if not self.active:
                return None
            if event.isSet():
                break
        try:
            self.lock.acquire()
            if not self.channels.has_key(chanid):
                chan = None
        finally:
            self.lock.release()
        return chan

    def unlink_channel(self, chanid):
        try:
            self.lock.acquire()
            if self.channels.has_key(chanid):
                del self.channels[chanid]
        finally:
            self.lock.release()

    def read_all(self, n):
        out = ''
        while n > 0:
            try:
                x = self.sock.recv(n)
                if len(x) == 0:
                    raise EOFError()
                out += x
                n -= len(x)
            except socket.timeout:
                if not self.active:
                    raise EOFError()
        return out

    def write_all(self, out):
        while len(out) > 0:
            n = self.sock.send(out)
            if n <= 0:
                raise EOFError()
            if n == len(out):
                return
            out = out[n:]
        return

    def build_packet(self, payload):
        # pad up at least 4 bytes, to nearest block-size (usually 8)
        bsize = self.block_size_out
        padding = 3 + bsize - ((len(payload) + 8) % bsize)
        packet = struct.pack('>I', len(payload) + padding + 1)
        packet += chr(padding)
        packet += payload
        packet += randpool.get_bytes(padding)
        return packet

    def send_message(self, data):
        # encrypt this sucka
        packet = self.build_packet(str(data))
        if self.ultra_debug:
            self.log(DEBUG, format_binary(packet, 'OUT: '))
        if self.engine_out != None:
            out = self.engine_out.encrypt(packet)
        else:
            out = packet
        # + mac
        try:
            self.write_lock.acquire()
            if self.engine_out != None:
                payload = struct.pack('>I', self.sequence_number_out) + packet
                out += HMAC.HMAC(self.mac_key_out, payload, self.local_mac_engine).digest()[:self.local_mac_len]
            self.sequence_number_out += 1L
            self.sequence_number_out %= 0x100000000L
            self.write_all(out)
        finally:
            self.write_lock.release()

    def read_message(self):
        "only one thread will ever be in this function"
        header = self.read_all(self.block_size_in)
        if self.engine_in != None:
            header = self.engine_in.decrypt(header)
        if self.ultra_debug:
            self.log(DEBUG, format_binary(header, 'IN: '));
        packet_size = struct.unpack('>I', header[:4])[0]
        # leftover contains decrypted bytes from the first block (after the length field)
        leftover = header[4:]
        if (packet_size - len(leftover)) % self.block_size_in != 0:
            raise SSHException('Invalid packet blocking')
        buffer = self.read_all(packet_size + self.remote_mac_len - len(leftover))
        packet = buffer[:packet_size - len(leftover)]
        post_packet = buffer[packet_size - len(leftover):]
        if self.engine_in != None:
            packet = self.engine_in.decrypt(packet)
        if self.ultra_debug:
            self.log(DEBUG, format_binary(packet, 'IN: '));
        packet = leftover + packet
        if self.remote_mac_len > 0:
            mac = post_packet[:self.remote_mac_len]
            mac_payload = struct.pack('>II', self.sequence_number_in, packet_size) + packet
            my_mac = HMAC.HMAC(self.mac_key_in, mac_payload, self.remote_mac_engine).digest()[:self.remote_mac_len]
            if my_mac != mac:
                raise SSHException('Mismatched MAC')
        padding = ord(packet[0])
        payload = packet[1:packet_size - padding + 1]
        randpool.add_event(packet[packet_size - padding + 1])
        #self.log(DEBUG, 'Got payload (%d bytes, %d padding)' % (packet_size, padding))
        msg = Message(payload[1:])
        msg.seqno = self.sequence_number_in
        self.sequence_number_in = (self.sequence_number_in + 1) & 0xffffffffL
        # check for rekey
        self.received_bytes += packet_size + self.remote_mac_len + 4
        self.received_packets += 1
        if (self.received_packets >= self.REKEY_PACKETS) or (self.received_bytes >= self.REKEY_BYTES):
            # only ask once for rekeying
            if self.local_kex_init is None:
                self.log(DEBUG, 'Rekeying (hit %d packets, %d bytes)' % (self.received_packets,
                                                                         self.received_bytes))
                self.received_packets_overflow = 0
                self.send_kex_init()
            else:
                # we've asked to rekey already -- give them 20 packets to
                # comply, then just drop the connection
                self.received_packets_overflow += 1
                if self.received_packets_overflow >= 20:
                    raise SSHException('Remote transport is ignoring rekey requests')
                
        return ord(payload[0]), msg

    def set_K_H(self, k, h):
        "used by a kex object to set the K (root key) and H (exchange hash)"
        self.K = k
        self.H = h
        if self.session_id == None:
            self.session_id = h

    def verify_key(self, host_key, sig):
        if self.host_key_type == 'ssh-rsa':
            key = RSAKey(Message(host_key))
        elif self.host_key_type == 'ssh-dss':
            key = DSSKey(Message(host_key))
        else:
            key = None
        if (key == None) or not key.valid:
            raise SSHException('Unknown host key type')
        if not key.verify_ssh_sig(self.H, Message(sig)):
            raise SSHException('Signature verification (%s) failed.  Boo.  Robey should debug this.' % self.host_key_type)
        self.host_key = host_key

    def compute_key(self, id, nbytes):
        "id is 'A' - 'F' for the various keys used by ssh"
        m = Message()
        m.add_mpint(self.K)
        m.add_bytes(self.H)
        m.add_byte(id)
        m.add_bytes(self.session_id)
        out = sofar = SHA.new(str(m)).digest()
        while len(out) < nbytes:
            m = Message()
            m.add_mpint(self.K)
            m.add_bytes(self.H)
            m.add_bytes(sofar)
            hash = SHA.new(str(m)).digest()
            out += hash
            sofar += hash
        return out[:nbytes]

    def get_cipher(self, name, key, iv):
        if not self.cipher_info.has_key(name):
            raise SSHException('Unknown client cipher ' + name)
        return self.cipher_info[name]['class'].new(key, self.cipher_info[name]['mode'], iv)

    def run(self):
        self.active = 1
        try:
            # SSH-1.99-OpenSSH_2.9p2
            self.write_all(self.local_version + '\r\n')
            self.check_banner()
            self.send_kex_init()
            self.expected_packet = MSG_KEXINIT

            while self.active:
                ptype, m = self.read_message()
                if ptype == MSG_IGNORE:
                    continue
                elif ptype == MSG_DISCONNECT:
                    self.parse_disconnect(m)
                    self.active = 0
                    break
                elif ptype == MSG_DEBUG:
                    self.parse_debug(m)
                    continue
                if self.expected_packet != 0:
                    if ptype != self.expected_packet:
                        raise SSHException('Expecting packet %d, got %d' % (self.expected_packet, ptype))
                    self.expected_packet = 0
                    if (ptype >= 30) and (ptype <= 39):
                        self.kex_engine.parse_next(ptype, m)
                        continue

                if self.handler_table.has_key(ptype):
                    self.handler_table[ptype](self, m)
                elif self.channel_handler_table.has_key(ptype):
                    chanid = m.get_int()
                    if self.channels.has_key(chanid):
                        self.channel_handler_table[ptype](self.channels[chanid], m)
                else:
                    self.log(WARNING, 'Oops, unhandled type %d' % ptype)
                    msg = Message()
                    msg.add_byte(chr(MSG_UNIMPLEMENTED))
                    msg.add_int(m.seqno)
                    self.send_message(msg)
        except SSHException, e:
            self.log(DEBUG, 'Exception: ' + str(e))
            self.log(DEBUG, tb_strings())
        except EOFError, e:
            self.log(DEBUG, 'EOF')
        except Exception, e:
            self.log(DEBUG, 'Unknown exception: ' + str(e))
            self.log(DEBUG, tb_strings())
        if self.active:
            self.active = 0
            if self.completion_event != None:
                self.completion_event.set()
            if self.auth_event != None:
                self.auth_event.set()
            for e in self.channel_events.values():
                e.set()
        self.sock.close()

    ###  protocol stages

    def renegotiate_keys(self):
        self.completion_event = threading.Event()
        self.send_kex_init()
        while 1:
            self.completion_event.wait(0.1);
            if not self.active:
                return 0
            if self.completion_event.isSet():
                break
        return 1

    def negotiate_keys(self, m):
        # throws SSHException on anything unusual
        if self.local_kex_init == None:
            # remote side wants to renegotiate
            self.send_kex_init()
        self.parse_kex_init(m)
        self.kex_engine.start_kex()

    def check_banner(self):
        # this is slow, but we only have to do it once
        for i in range(5):
            buffer = ''
            while not '\n' in buffer:
                buffer += self.read_all(1)
            buffer = buffer[:-1]
            if (len(buffer) > 0) and (buffer[-1] == '\r'):
                buffer = buffer[:-1]
            if buffer[:4] == 'SSH-':
                break
            self.log(DEBUG, 'Banner: ' + buffer)
        if buffer[:4] != 'SSH-':
            raise SSHException('Indecipherable protocol version "' + buffer + '"')
        # save this server version string for later
        self.remote_version = buffer
        # pull off any attached comment
        comment = ''
        i = string.find(buffer, ' ')
        if i >= 0:
            comment = buffer[i+1:]
            buffer = buffer[:i]
        # parse out version string and make sure it matches
        segs = buffer.split('-', 2)
        if len(segs) < 3:
            raise SSHException('Invalid SSH banner')
        version = segs[1]
        client = segs[2]
        if version != '1.99' and version != '2.0':
            raise SSHException('Incompatible version (%s instead of 2.0)' % (version,))
        self.log(INFO, 'Connected (version %s, client %s)' % (version, client))

    def send_kex_init(self):
        # send a really wimpy kex-init packet that says we're a bare-bones ssh client
        if self.server_mode:
            # FIXME: can't do group-exchange (gex) yet -- too slow
            if 'diffie-hellman-group-exchange-sha1' in self.preferred_kex:
                self.preferred_kex.remove('diffie-hellman-group-exchange-sha1')

        available_server_keys = filter(self.server_key_dict.keys().__contains__,
                                       self.preferred_keys)

        m = Message()
        m.add_byte(chr(MSG_KEXINIT))
        m.add_bytes(randpool.get_bytes(16))
        m.add(','.join(self.preferred_kex))
        m.add(','.join(available_server_keys))
        m.add(','.join(self.preferred_ciphers))
        m.add(','.join(self.preferred_ciphers))
        m.add(','.join(self.preferred_macs))
        m.add(','.join(self.preferred_macs))
        m.add('none')
        m.add('none')
        m.add('')
        m.add('')
        m.add_boolean(0)
        m.add_int(0)
        # save a copy for later (needed to compute a hash)
        self.local_kex_init = str(m)
        self.send_message(m)

    def parse_kex_init(self, m):
        # reset counters of when to re-key, since we are now re-keying
        self.received_bytes = 0
        self.received_packets = 0
        self.received_packets_overflow = 0

        cookie = m.get_bytes(16)
        kex_algo_list = m.get_list()
        server_key_algo_list = m.get_list()
        client_encrypt_algo_list = m.get_list()
        server_encrypt_algo_list = m.get_list()
        client_mac_algo_list = m.get_list()
        server_mac_algo_list = m.get_list()
        client_compress_algo_list = m.get_list()
        server_compress_algo_list = m.get_list()
        client_lang_list = m.get_list()
        server_lang_list = m.get_list()
        kex_follows = m.get_boolean()
        unused = m.get_int()

        # no compression support (yet?)
        if (not('none' in client_compress_algo_list) or
            not('none' in server_compress_algo_list)):
            raise SSHException('Incompatible ssh peer.')

        # as a server, we pick the first item in the client's list that we support.
        # as a client, we pick the first item in our list that the server supports.
        if self.server_mode:
            agreed_kex = filter(self.preferred_kex.__contains__, kex_algo_list)
        else:
            agreed_kex = filter(kex_algo_list.__contains__, self.preferred_kex)
        if len(agreed_kex) == 0:
            raise SSHException('Incompatible ssh peer (no acceptable kex algorithm)')
        self.kex_engine = self.kex_info[agreed_kex[0]](self)

        if self.server_mode:
            available_server_keys = filter(self.server_key_dict.keys().__contains__,
                                           self.preferred_keys)
            agreed_keys = filter(available_server_keys.__contains__, server_key_algo_list)
        else:
            agreed_keys = filter(server_key_algo_list.__contains__, self.preferred_keys)
        if len(agreed_keys) == 0:
            raise SSHException('Incompatible ssh peer (no acceptable host key)')
        self.host_key_type = agreed_keys[0]
        if self.server_mode and (self.get_server_key() is None):
            raise SSHException('Incompatible ssh peer (can\'t match requested host key type)')

        if self.server_mode:
            agreed_local_ciphers = filter(self.preferred_ciphers.__contains__,
                                           server_encrypt_algo_list)
            agreed_remote_ciphers = filter(self.preferred_ciphers.__contains__,
                                          client_encrypt_algo_list)
        else:
            agreed_local_ciphers = filter(client_encrypt_algo_list.__contains__,
                                          self.preferred_ciphers)
            agreed_remote_ciphers = filter(server_encrypt_algo_list.__contains__,
                                           self.preferred_ciphers)
        if (len(agreed_local_ciphers) == 0) or (len(agreed_remote_ciphers) == 0):
            raise SSHException('Incompatible ssh server (no acceptable ciphers)')
        self.local_cipher = agreed_local_ciphers[0]
        self.remote_cipher = agreed_remote_ciphers[0]
        self.log(DEBUG, 'Ciphers agreed: local=%s, remote=%s' % (self.local_cipher, self.remote_cipher))

        if self.server_mode:
            agreed_remote_macs = filter(self.preferred_macs.__contains__, client_mac_algo_list)
            agreed_local_macs = filter(self.preferred_macs.__contains__, server_mac_algo_list)
        else:
            agreed_local_macs = filter(client_mac_algo_list.__contains__, self.preferred_macs)
            agreed_remote_macs = filter(server_mac_algo_list.__contains__, self.preferred_macs)
        if (len(agreed_local_macs) == 0) or (len(agreed_remote_macs) == 0):
            raise SSHException('Incompatible ssh server (no acceptable macs)')
        self.local_mac = agreed_local_macs[0]
        self.remote_mac = agreed_remote_macs[0]

        self.log(DEBUG, 'kex algos:' + str(kex_algo_list) + ' server key:' + str(server_key_algo_list) + \
                 ' client encrypt:' + str(client_encrypt_algo_list) + \
                 ' server encrypt:' + str(server_encrypt_algo_list) + \
                 ' client mac:' + str(client_mac_algo_list) + \
                 ' server mac:' + str(server_mac_algo_list) + \
                 ' client compress:' + str(client_compress_algo_list) + \
                 ' server compress:' + str(server_compress_algo_list) + \
                 ' client lang:' + str(client_lang_list) + \
                 ' server lang:' + str(server_lang_list) + \
                 ' kex follows?' + str(kex_follows))
        self.log(DEBUG, 'using kex %s; server key type %s; cipher: local %s, remote %s; mac: local %s, remote %s' %
                 (agreed_kex[0], self.host_key_type, self.local_cipher, self.remote_cipher, self.local_mac,
                  self.remote_mac))

        # save for computing hash later...
        # now wait!  openssh has a bug (and others might too) where there are
        # actually some extra bytes (one NUL byte in openssh's case) added to
        # the end of the packet but not parsed.  turns out we need to throw
        # away those bytes because they aren't part of the hash.
        self.remote_kex_init = chr(MSG_KEXINIT) + m.get_so_far()

    def activate_inbound(self):
        "switch on newly negotiated encryption parameters for inbound traffic"
        self.block_size_in = self.cipher_info[self.remote_cipher]['block-size']
        if self.server_mode:
            IV_in = self.compute_key('A', self.block_size_in)
            key_in = self.compute_key('C', self.cipher_info[self.remote_cipher]['key-size'])
        else:
            IV_in = self.compute_key('B', self.block_size_in)
            key_in = self.compute_key('D', self.cipher_info[self.remote_cipher]['key-size'])
        self.engine_in = self.get_cipher(self.remote_cipher, key_in, IV_in)
        self.remote_mac_len = self.mac_info[self.remote_mac]['size']
        self.remote_mac_engine = self.mac_info[self.remote_mac]['class']
        # initial mac keys are done in the hash's natural size (not the potentially truncated
        # transmission size)
        if self.server_mode:
            self.mac_key_in = self.compute_key('E', self.remote_mac_engine.digest_size)
        else:
            self.mac_key_in = self.compute_key('F', self.remote_mac_engine.digest_size)

    def activate_outbound(self):
        "switch on newly negotiated encryption parameters for outbound traffic"
        m = Message()
        m.add_byte(chr(MSG_NEWKEYS))
        self.send_message(m)
        self.block_size_out = self.cipher_info[self.local_cipher]['block-size']
        if self.server_mode:
            IV_out = self.compute_key('B', self.block_size_out)
            key_out = self.compute_key('D', self.cipher_info[self.local_cipher]['key-size'])
        else:
            IV_out = self.compute_key('A', self.block_size_out)
            key_out = self.compute_key('C', self.cipher_info[self.local_cipher]['key-size'])
        self.engine_out = self.get_cipher(self.local_cipher, key_out, IV_out)
        self.local_mac_len = self.mac_info[self.local_mac]['size']
        self.local_mac_engine = self.mac_info[self.local_mac]['class']
        # initial mac keys are done in the hash's natural size (not the potentially truncated
        # transmission size)
        if self.server_mode:
            self.mac_key_out = self.compute_key('F', self.local_mac_engine.digest_size)
        else:
            self.mac_key_out = self.compute_key('E', self.local_mac_engine.digest_size)

    def parse_newkeys(self, m):
        self.log(DEBUG, 'Switch to new keys ...')
        self.activate_inbound()
        # can also free a bunch of stuff here
        self.local_kex_init = self.remote_kex_init = None
        self.e = self.f = self.K = self.x = None
        if not self.initial_kex_done:
            # this was the first key exchange
            self.initial_kex_done = 1
        # send an event?
        if self.completion_event != None:
            self.completion_event.set()
        return

    def parse_disconnect(self, m):
        code = m.get_int()
        desc = m.get_string()
        self.log(INFO, 'Disconnect (code %d): %s' % (code, desc))

    def parse_channel_open_success(self, m):
        chanid = m.get_int()
        server_chanid = m.get_int()
        server_window_size = m.get_int()
        server_max_packet_size = m.get_int()
        if not self.channels.has_key(chanid):
            self.log(WARNING, 'Success for unrequested channel! [??]')
            return
        try:
            self.lock.acquire()
            chan = self.channels[chanid]
            chan.set_remote_channel(server_chanid, server_window_size, server_max_packet_size)
            self.log(INFO, 'Secsh channel %d opened.' % chanid)
            if self.channel_events.has_key(chanid):
                self.channel_events[chanid].set()
                del self.channel_events[chanid]
        finally:
            self.lock.release()
        return

    def parse_channel_open_failure(self, m):
        chanid = m.get_int()
        reason = m.get_int()
        reason_str = m.get_string()
        lang = m.get_string()
        if CONNECTION_FAILED_CODE.has_key(reason):
            reason_text = CONNECTION_FAILED_CODE[reason]
        else:
            reason_text = '(unknown code)'
        self.log(INFO, 'Secsh channel %d open FAILED: %s: %s' % (chanid, reason_str, reason_text))
        try:
            self.lock.aquire()
            if self.channels.has_key(chanid):
                del self.channels[chanid]
                if self.channel_events.has_key(chanid):
                    self.channel_events[chanid].set()
                    del self.channel_events[chanid]
        finally:
            self.lock.release()
        return

    def check_channel_request(self, kind, chanid):
        "override me!  return object descended from Channel to allow, or None to reject"
        return None

    def parse_channel_open(self, m):
        kind = m.get_string()
        chanid = m.get_int()
        initial_window_size = m.get_int()
        max_packet_size = m.get_int()
        reject = False
        if not self.server_mode:
            self.log(DEBUG, 'Rejecting "%s" channel request from server.' % kind)
            reject = True
            reason = self.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        else:
            try:
                self.lock.acquire()
                my_chanid = self.channel_counter
                self.channel_counter += 1
            finally:
                self.lock.release()
            chan = self.check_channel_request(kind, my_chanid)
            if (chan is None) or (type(chan) is int):
                self.log(DEBUG, 'Rejecting "%s" channel request from client.' % kind)
                reject = True
                if type(chan) is int:
                    reason = chan
                else:
                    reason = self.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        if reject:
            msg = Message()
            msg.add_byte(chr(MSG_CHANNEL_OPEN_FAILURE))
            msg.add_int(chanid)
            msg.add_int(reason)
            msg.add_string('')
            msg.add_string('en')
            self.send_message(msg)
            return
        try:
            self.lock.acquire()
            self.channels[my_chanid] = chan
            chan.set_transport(self)
            chan.set_window(self.window_size, self.max_packet_size)
            chan.set_remote_channel(chanid, initial_window_size, max_packet_size)
        finally:
            self.lock.release()
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_OPEN_SUCCESS))
        m.add_int(chanid)
        m.add_int(my_chanid)
        m.add_int(self.window_size)
        m.add_int(self.max_packet_size)
        self.send_message(m)
        self.log(INFO, 'Secsh channel %d opened.' % my_chanid)
        try:
            self.lock.acquire()
            self.server_accepts.append(chan)
            self.server_accept_cv.notify()
        finally:
            self.lock.release()

    def accept(self, timeout=None):
        try:
            self.lock.acquire()
            if len(self.server_accepts) > 0:
                chan = self.server_accepts.pop(0)
            else:
                self.server_accept_cv.wait(timeout)
                if len(self.server_accepts) > 0:
                    chan = self.server_accepts.pop(0)
                else:
                    # timeout
                    chan = None
        finally:
            self.lock.release()
        return chan

    def parse_debug(self, m):
        always_display = m.get_boolean()
        msg = m.get_string()
        lang = m.get_string()
        self.log(DEBUG, 'Debug msg: ' + safe_string(msg))

    handler_table = {
        MSG_NEWKEYS: parse_newkeys,
        MSG_CHANNEL_OPEN_SUCCESS: parse_channel_open_success,
        MSG_CHANNEL_OPEN_FAILURE: parse_channel_open_failure,
        MSG_CHANNEL_OPEN: parse_channel_open,
        MSG_KEXINIT: negotiate_keys,
        }

    channel_handler_table = {
        MSG_CHANNEL_SUCCESS: Channel.request_success,
        MSG_CHANNEL_FAILURE: Channel.request_failed,
        MSG_CHANNEL_DATA: Channel.feed,
        MSG_CHANNEL_WINDOW_ADJUST: Channel.window_adjust,
        MSG_CHANNEL_REQUEST: Channel.handle_request,
        MSG_CHANNEL_EOF: Channel.handle_eof,
        MSG_CHANNEL_CLOSE: Channel.handle_close,
        }
