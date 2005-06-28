# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
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
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Packetizer.
"""

import select, socket, struct, threading, time
from Crypto.Hash import HMAC
from common import *
from ssh_exception import SSHException
from message import Message
import util


class Packetizer (object):
    """
    Implementation of the base SSH packet protocol.
    """

    # READ the secsh RFC's before raising these values.  if anything,
    # they should probably be lower.
    REKEY_PACKETS = pow(2, 30)
    REKEY_BYTES = pow(2, 30)
    
    def __init__(self, socket):
        self.__socket = socket
        self.__logger = None
        self.__closed = False
        self.__dump_packets = False
        self.__need_rekey = False
        self.__init_count = 0
        
        # used for noticing when to re-key:
        self.__sent_bytes = 0
        self.__sent_packets = 0
        self.__received_bytes = 0
        self.__received_packets = 0
        self.__received_packets_overflow = 0

        # current inbound/outbound ciphering:
        self.__block_size_out = 8
        self.__block_size_in = 8
        self.__mac_size_out = 0
        self.__mac_size_in = 0
        self.__block_engine_out = None
        self.__block_engine_in = None
        self.__mac_engine_out = None
        self.__mac_engine_in = None
        self.__mac_key_out = ''
        self.__mac_key_in = ''
        self.__sequence_number_out = 0L
        self.__sequence_number_in = 0L

        # lock around outbound writes (packet computation)
        self.__write_lock = threading.RLock()

        # keepalives:
        self.__keepalive_interval = 0
        self.__keepalive_last = time.time()
        self.__keepalive_callback = None
        
    def __del__(self):
        # this is not guaranteed to be called, but we should try.
        try:
            self.__socket.close()
        except:
            pass

    def set_log(self, log):
        """
        Set the python log object to use for logging.
        """
        self.__logger = log
    
    def set_outbound_cipher(self, block_engine, block_size, mac_engine, mac_size, mac_key):
        """
        Switch outbound data cipher.
        """
        self.__block_engine_out = block_engine
        self.__block_size_out = block_size
        self.__mac_engine_out = mac_engine
        self.__mac_size_out = mac_size
        self.__mac_key_out = mac_key
        self.__sent_bytes = 0
        self.__sent_packets = 0
        # wait until the reset happens in both directions before clearing rekey flag
        self.__init_count |= 1
        if self.__init_count == 3:
            self.__init_count = 0
            self.__need_rekey = False
    
    def set_inbound_cipher(self, block_engine, block_size, mac_engine, mac_size, mac_key):
        """
        Switch inbound data cipher.
        """
        self.__block_engine_in = block_engine
        self.__block_size_in = block_size
        self.__mac_engine_in = mac_engine
        self.__mac_size_in = mac_size
        self.__mac_key_in = mac_key
        self.__received_bytes = 0
        self.__received_packets = 0
        self.__received_packets_overflow = 0
        # wait until the reset happens in both directions before clearing rekey flag
        self.__init_count |= 2
        if self.__init_count == 3:
            self.__init_count = 0
            self.__need_rekey = False
    
    def close(self):
        self.__closed = True

    def set_hexdump(self, hexdump):
        self.__dump_packets = hexdump
        
    def get_hexdump(self):
        return self.__dump_packets
    
    def get_mac_size_in(self):
        return self.__mac_size_in
    
    def get_mac_size_out(self):
        return self.__mac_size_out

    def need_rekey(self):
        """
        Returns C{True} if a new set of keys needs to be negotiated.  This
        will be triggered during a packet read or write, so it should be
        checked after every read or write, or at least after every few.
        
        @return: C{True} if a new set of keys needs to be negotiated
        """
        return self.__need_rekey
    
    def set_keepalive(self, interval, callback):
        """
        Turn on/off the callback keepalive.  If C{interval} seconds pass with
        no data read from or written to the socket, the callback will be
        executed and the timer will be reset.
        """
        self.__keepalive_interval = interval
        self.__keepalive_callback = callback
        self.__keepalive_last = time.time()
    
    def read_all(self, n):
        """
        Read as close to N bytes as possible, blocking as long as necessary.
        
        @param n: number of bytes to read
        @type n: int
        @return: the data read
        @rtype: str
        @throw EOFError: if the socket was closed before all the bytes could
            be read
        """
        if PY22:
            return self._py22_read_all(n)
        out = ''
        while n > 0:
            try:
                x = self.__socket.recv(n)
                if len(x) == 0:
                    raise EOFError()
                out += x
                n -= len(x)
            except socket.timeout:
                if self.__closed:
                    raise EOFError()
                self._check_keepalive()
        return out

    def write_all(self, out):
        self.__keepalive_last = time.time()
        while len(out) > 0:
            try:
                n = self.__socket.send(out)
            except socket.timeout:
                n = 0
                if self.__closed:
                    n = -1
            except Exception, x:
                # could be: (32, 'Broken pipe')
                n = -1
            if n < 0:
                raise EOFError()
            if n == len(out):
                return
            out = out[n:]
        return
        
    def readline(self, timeout):
        """
        Read a line from the socket.  This is done in a fairly inefficient
        way, but is only used for initial banner negotiation so it's not worth
        optimising.
        """
        buffer = ''
        while not '\n' in buffer:
            buffer += self._read_timeout(timeout)
        buffer = buffer[:-1]
        if (len(buffer) > 0) and (buffer[-1] == '\r'):
            buffer = buffer[:-1]
        return buffer

    def send_message(self, data):
        """
        Write a block of data using the current cipher, as an SSH block.
        """
        # encrypt this sucka
        data = str(data)
        cmd = ord(data[0])
        if cmd in MSG_NAMES:
            cmd_name = MSG_NAMES[cmd]
        else:
            cmd_name = '$%x' % cmd
        self._log(DEBUG, 'Write packet <%s>, length %d' % (cmd_name, len(data)))
        packet = self._build_packet(data)
        if self.__dump_packets:
            self._log(DEBUG, util.format_binary(packet, 'OUT: '))
        self.__write_lock.acquire()
        try:
            if self.__block_engine_out != None:
                out = self.__block_engine_out.encrypt(packet)
            else:
                out = packet
            # + mac
            if self.__block_engine_out != None:
                payload = struct.pack('>I', self.__sequence_number_out) + packet
                out += HMAC.HMAC(self.__mac_key_out, payload, self.__mac_engine_out).digest()[:self.__mac_size_out]
            self.__sequence_number_out = (self.__sequence_number_out + 1) & 0xffffffffL
            self.write_all(out)

            self.__sent_bytes += len(out)
            self.__sent_packets += 1
            if ((self.__sent_packets >= self.REKEY_PACKETS) or (self.__sent_bytes >= self.REKEY_BYTES)) \
                   and not self.__need_rekey:
                # only ask once for rekeying
                self._log(DEBUG, 'Rekeying (hit %d packets, %d bytes sent)' %
                          (self.__sent_packets, self.__sent_bytes))
                self.__received_packets_overflow = 0
                self._trigger_rekey()
        finally:
            self.__write_lock.release()

    def read_message(self):
        """
        Only one thread should ever be in this function (no other locking is
        done).
        
        @throw SSHException: if the packet is mangled
        """
        header = self.read_all(self.__block_size_in)
        if self.__block_engine_in != None:
            header = self.__block_engine_in.decrypt(header)
        if self.__dump_packets:
            self._log(DEBUG, util.format_binary(header, 'IN: '));
        packet_size = struct.unpack('>I', header[:4])[0]
        # leftover contains decrypted bytes from the first block (after the length field)
        leftover = header[4:]
        if (packet_size - len(leftover)) % self.__block_size_in != 0:
            raise SSHException('Invalid packet blocking')
        buffer = self.read_all(packet_size + self.__mac_size_in - len(leftover))
        packet = buffer[:packet_size - len(leftover)]
        post_packet = buffer[packet_size - len(leftover):]
        if self.__block_engine_in != None:
            packet = self.__block_engine_in.decrypt(packet)
        if self.__dump_packets:
            self._log(DEBUG, util.format_binary(packet, 'IN: '));
        packet = leftover + packet

        if self.__mac_size_in > 0:
            mac = post_packet[:self.__mac_size_in]
            mac_payload = struct.pack('>II', self.__sequence_number_in, packet_size) + packet
            my_mac = HMAC.HMAC(self.__mac_key_in, mac_payload, self.__mac_engine_in).digest()[:self.__mac_size_in]
            if my_mac != mac:
                raise SSHException('Mismatched MAC')
        padding = ord(packet[0])
        payload = packet[1:packet_size - padding + 1]
        randpool.add_event(packet[packet_size - padding + 1])
        if self.__dump_packets:
            self._log(DEBUG, 'Got payload (%d bytes, %d padding)' % (packet_size, padding))

        msg = Message(payload[1:])
        msg.seqno = self.__sequence_number_in
        self.__sequence_number_in = (self.__sequence_number_in + 1) & 0xffffffffL
        
        # check for rekey
        self.__received_bytes += packet_size + self.__mac_size_in + 4
        self.__received_packets += 1
        if self.__need_rekey:
            # we've asked to rekey -- give them 20 packets to comply before
            # dropping the connection
            self.__received_packets_overflow += 1
            if self.__received_packets_overflow >= 20:
                raise SSHException('Remote transport is ignoring rekey requests')
        elif (self.__received_packets >= self.REKEY_PACKETS) or \
             (self.__received_bytes >= self.REKEY_BYTES):
            # only ask once for rekeying
            self._log(DEBUG, 'Rekeying (hit %d packets, %d bytes received)' %
                      (self.__received_packets, self.__received_bytes))
            self.__received_packets_overflow = 0
            self._trigger_rekey()

        cmd = ord(payload[0])
        if cmd in MSG_NAMES:
            cmd_name = MSG_NAMES[cmd]
        else:
            cmd_name = '$%x' % cmd
        self._log(DEBUG, 'Read packet <%s>, length %d' % (cmd_name, len(payload)))
        return cmd, msg


    ##########  protected
    
    
    def _log(self, level, msg):
        if self.__logger is None:
            return
        if issubclass(type(msg), list):
            for m in msg:
                self.__logger.log(level, m)
        else:
            self.__logger.log(level, msg)

    def _check_keepalive(self):
        if (not self.__keepalive_interval) or (not self.__block_engine_out) or \
            self.__need_rekey:
            # wait till we're encrypting, and not in the middle of rekeying
            return
        now = time.time()
        if now > self.__keepalive_last + self.__keepalive_interval:
            self.__keepalive_callback()
            self.__keepalive_last = now
    
    def _py22_read_all(self, n):
        out = ''
        while n > 0:
            r, w, e = select.select([self.__socket], [], [], 0.1)
            if self.__socket not in r:
                if self.__closed:
                    raise EOFError()
                self._check_keepalive()
            else:
                x = self.__socket.recv(n)
                if len(x) == 0:
                    raise EOFError()
                out += x
                n -= len(x)
        return out

    def _py22_read_timeout(self, timeout):
        start = time.time()
        while True:
            r, w, e = select.select([self.__socket], [], [], 0.1)
            if self.__socket in r:
                x = self.__socket.recv(1)
                if len(x) == 0:
                    raise EOFError()
                return x
            if self.__closed:
                raise EOFError()
            now = time.time()
            if now - start >= timeout:
                raise socket.timeout()

    def _read_timeout(self, timeout):
        if PY22:
            return self._py22_read_timeout(n)
        start = time.time()
        while True:
            try:
                x = self.__socket.recv(1)
                if len(x) == 0:
                    raise EOFError()
                return x
            except socket.timeout:
                pass
            if self.__closed:
                raise EOFError()
            now = time.time()
            if now - start >= timeout:
                raise socket.timeout()

    def _build_packet(self, payload):
        # pad up at least 4 bytes, to nearest block-size (usually 8)
        bsize = self.__block_size_out
        padding = 3 + bsize - ((len(payload) + 8) % bsize)
        packet = struct.pack('>IB', len(payload) + padding + 1, padding)
        packet += payload
        if self.__block_engine_out is not None:
            packet += randpool.get_bytes(padding)
        else:
            # cute trick i caught openssh doing: if we're not encrypting,
            # don't waste random bytes for the padding
            packet += (chr(0) * padding)
        return packet

    def _trigger_rekey(self):
        # outside code should check for this flag
        self.__need_rekey = True
