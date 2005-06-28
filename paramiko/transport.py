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
L{BaseTransport} handles the core SSH2 protocol.
"""

import sys, os, string, threading, socket, struct, time

from common import *
from ssh_exception import SSHException
from message import Message
from channel import Channel
from sftp_client import SFTPClient
import util
from packet import Packetizer
from rsakey import RSAKey
from dsskey import DSSKey
from kex_group1 import KexGroup1
from kex_gex import KexGex
from primes import ModulusPack

# these come from PyCrypt
#     http://www.amk.ca/python/writing/pycrypt/
# i believe this on the standards track.
# PyCrypt compiled for Win32 can be downloaded from the HashTar homepage:
#     http://nitace.bsd.uchicago.edu:8080/hashtar
from Crypto.Cipher import Blowfish, AES, DES3
from Crypto.Hash import SHA, MD5, HMAC


# for thread cleanup
_active_threads = []
def _join_lingering_threads():
    for thr in _active_threads:
        thr.stop_thread()
import atexit
atexit.register(_join_lingering_threads)


class SecurityOptions (object):
    """
    Simple object containing the security preferences of an ssh transport.
    These are tuples of acceptable ciphers, digests, key types, and key
    exchange algorithms, listed in order of preference.

    Changing the contents and/or order of these fields affects the underlying
    L{Transport} (but only if you change them before starting the session).
    If you try to add an algorithm that paramiko doesn't recognize,
    C{ValueError} will be raised.  If you try to assign something besides a
    tuple to one of the fields, C{TypeError} will be raised.

    @since: ivysaur
    """
    __slots__ = [ 'ciphers', 'digests', 'key_types', 'kex', '_transport' ]

    def __init__(self, transport):
        self._transport = transport

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.

        @rtype: str
        """
        return '<paramiko.SecurityOptions for %s>' % repr(self._transport)

    def _get_ciphers(self):
        return self._transport._preferred_ciphers

    def _get_digests(self):
        return self._transport._preferred_macs

    def _get_key_types(self):
        return self._transport._preferred_keys

    def _get_kex(self):
        return self._transport._preferred_kex

    def _set(self, name, orig, x):
        if type(x) is list:
            x = tuple(x)
        if type(x) is not tuple:
            raise TypeError('expected tuple or list')
        possible = getattr(self._transport, orig).keys()
        if len(filter(lambda n: n not in possible, x)) > 0:
            raise ValueError('unknown cipher')
        setattr(self._transport, name, x)

    def _set_ciphers(self, x):
        self._set('_preferred_ciphers', '_cipher_info', x)

    def _set_digests(self, x):
        self._set('_preferred_macs', '_mac_info', x)

    def _set_key_types(self, x):
        self._set('_preferred_keys', '_key_info', x)

    def _set_kex(self, x):
        self._set('_preferred_kex', '_kex_info', x)

    ciphers = property(_get_ciphers, _set_ciphers, None,
                       "Symmetric encryption ciphers")
    digests = property(_get_digests, _set_digests, None,
                       "Digest (one-way hash) algorithms")
    key_types = property(_get_key_types, _set_key_types, None,
                         "Public-key algorithms")
    kex = property(_get_kex, _set_kex, None, "Key exchange algorithms")


class BaseTransport (threading.Thread):
    """
    Handles protocol negotiation, key exchange, encryption, and the creation
    of channels across an SSH session.  Basically everything but authentication
    is done here.
    """
    _PROTO_ID = '2.0'
    _CLIENT_ID = 'paramiko_1.3'

    _preferred_ciphers = ( 'aes128-cbc', 'blowfish-cbc', 'aes256-cbc', '3des-cbc' )
    _preferred_macs = ( 'hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96' )
    _preferred_keys = ( 'ssh-rsa', 'ssh-dss' )
    _preferred_kex = ( 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1' )

    _cipher_info = {
        'blowfish-cbc': { 'class': Blowfish, 'mode': Blowfish.MODE_CBC, 'block-size': 8, 'key-size': 16 },
        'aes128-cbc': { 'class': AES, 'mode': AES.MODE_CBC, 'block-size': 16, 'key-size': 16 },
        'aes256-cbc': { 'class': AES, 'mode': AES.MODE_CBC, 'block-size': 16, 'key-size': 32 },
        '3des-cbc': { 'class': DES3, 'mode': DES3.MODE_CBC, 'block-size': 8, 'key-size': 24 },
        }

    _mac_info = {
        'hmac-sha1': { 'class': SHA, 'size': 20 },
        'hmac-sha1-96': { 'class': SHA, 'size': 12 },
        'hmac-md5': { 'class': MD5, 'size': 16 },
        'hmac-md5-96': { 'class': MD5, 'size': 12 },
        }

    _key_info = {
        'ssh-rsa': RSAKey,
        'ssh-dss': DSSKey,
        }

    _kex_info = {
        'diffie-hellman-group1-sha1': KexGroup1,
        'diffie-hellman-group-exchange-sha1': KexGex,
        }


    _modulus_pack = None

    def __init__(self, sock):
        """
        Create a new SSH session over an existing socket, or socket-like
        object.  This only creates the Transport object; it doesn't begin the
        SSH session yet.  Use L{connect} or L{start_client} to begin a client
        session, or L{start_server} to begin a server session.

        If the object is not actually a socket, it must have the following
        methods:
            - C{send(str)}: Writes from 1 to C{len(str)} bytes, and
              returns an int representing the number of bytes written.  Returns
              0 or raises C{EOFError} if the stream has been closed.
            - C{recv(int)}: Reads from 1 to C{int} bytes and returns them as a
              string.  Returns 0 or raises C{EOFError} if the stream has been
              closed.
            - C{close()}: Closes the socket.
            - C{settimeout(n)}: Sets a (float) timeout on I/O operations.

        For ease of use, you may also pass in an address (as a tuple) or a host
        string as the C{sock} argument.  (A host string is a hostname with an
        optional port (separated by C{":"}) which will be converted into a
        tuple of C{(hostname, port)}.)  A socket will be connected to this
        address and used for communication.  Exceptions from the C{socket} call
        may be thrown in this case.

        @param sock: a socket or socket-like object to create the session over.
        @type sock: socket
        """
        if type(sock) is str:
            # convert "host:port" into (host, port)
            hl = sock.split(':', 1)
            if len(hl) == 1:
                sock = (hl[0], 22)
            else:
                sock = (hl[0], int(hl[1]))
        if type(sock) is tuple:
            # connect to the given (host, port)
            hostname, port = sock
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((hostname, port))
        # okay, normal socket-ish flow here...
        threading.Thread.__init__(self, target=self._run)
        self.randpool = randpool
        self.sock = sock
        # Python < 2.3 doesn't have the settimeout method - RogerB
        try:
            # we set the timeout so we can check self.active periodically to
            # see if we should bail.  socket.timeout exception is never
            # propagated.
            self.sock.settimeout(0.1)
        except AttributeError:
            pass
        # negotiated crypto parameters
        self.packetizer = Packetizer(sock)
        self.local_version = 'SSH-' + self._PROTO_ID + '-' + self._CLIENT_ID
        self.remote_version = ''
        self.local_cipher = self.remote_cipher = ''
        self.local_kex_init = self.remote_kex_init = None
        self.session_id = None
        # /negotiated crypto parameters
        self.expected_packet = 0
        self.active = False
        self.initial_kex_done = False
        self.in_kex = False
        self.lock = threading.Lock()    # synchronization (always higher level than write_lock)
        self.channels = { }             # (id -> Channel)
        self.channel_events = { }       # (id -> Event)
        self.channel_counter = 1
        self.window_size = 65536
        self.max_packet_size = 32768
        self.saved_exception = None
        self.clear_to_send = threading.Event()
        self.log_name = 'paramiko.transport'
        self.logger = util.get_logger(self.log_name)
        self.packetizer.set_log(self.logger)
        # user-defined event callbacks:
        self.completion_event = None
        # server mode:
        self.server_mode = False
        self.server_object = None
        self.server_key_dict = { }
        self.server_accepts = [ ]
        self.server_accept_cv = threading.Condition(self.lock)
        self.subsystem_table = { }

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.

        @rtype: str
        """
        out = '<paramiko.BaseTransport at %s' % hex(long(id(self)) & 0xffffffffL)
        if not self.active:
            out += ' (unconnected)'
        else:
            if self.local_cipher != '':
                out += ' (cipher %s, %d bits)' % (self.local_cipher,
                                                  self._cipher_info[self.local_cipher]['key-size'] * 8)
            if len(self.channels) == 1:
                out += ' (active; 1 open channel)'
            else:
                out += ' (active; %d open channels)' % len(self.channels)
        out += '>'
        return out

    def get_security_options(self):
        """
        Return a L{SecurityOptions} object which can be used to tweak the
        encryption algorithms this transport will permit, and the order of
        preference for them.

        @return: an object that can be used to change the preferred algorithms
            for encryption, digest (hash), public key, and key exchange.
        @rtype: L{SecurityOptions}

        @since: ivysaur
        """
        return SecurityOptions(self)

    def start_client(self, event=None):
        """
        Negotiate a new SSH2 session as a client.  This is the first step after
        creating a new L{Transport}.  A separate thread is created for protocol
        negotiation, so this method returns immediately.
        
        When negotiation is done (successful or not), the given C{Event} will
        be triggered.  On failure, L{is_active} will return C{False}.

        After a successful negotiation, you will usually want to authenticate,
        calling L{auth_password <Transport.auth_password>} or
        L{auth_publickey <Transport.auth_publickey>}.

        @note: L{connect} is a simpler method for connecting as a client.
        
        @note: After calling this method (or L{start_server} or L{connect}),
            you should no longer directly read from or write to the original
            socket object.

        @param event: an event to trigger when negotiation is complete.
        @type event: threading.Event
        """
        self.completion_event = event
        self.active = True
        self.start()

    def start_server(self, event=None, server=None):
        """
        Negotiate a new SSH2 session as a server.  This is the first step after
        creating a new L{Transport} and setting up your server host key(s).  A
        separate thread is created for protocol negotiation, so this method
        returns immediately.

        When negotiation is done (successful or not), the given C{Event} will
        be triggered.  On failure, L{is_active} will return C{False}.

        After a successful negotiation, the client will need to authenticate.
        Override the methods
        L{get_allowed_auths <ServerInterface.get_allowed_auths>},
        L{check_auth_none <ServerInterface.check_auth_none>},
        L{check_auth_password <ServerInterface.check_auth_password>}, and
        L{check_auth_publickey <ServerInterface.check_auth_publickey>} in the
        given C{server} object to control the authentication process.

        After a successful authentication, the client should request to open
        a channel.  Override
        L{check_channel_request <ServerInterface.check_channel_request>} in the
        given C{server} object to allow channels to be opened.

        @note: After calling this method (or L{start_client} or L{connect}),
            you should no longer directly read from or write to the original
            socket object.

        @param event: an event to trigger when negotiation is complete.
        @type event: threading.Event
        @param server: an object used to perform authentication and create
            L{Channel}s.
        @type server: L{server.ServerInterface}
        """
        if server is None:
            server = ServerInterface()
        self.server_mode = True
        self.server_object = server
        self.completion_event = event
        self.active = True
        self.start()

    def add_server_key(self, key):
        """
        Add a host key to the list of keys used for server mode.  When behaving
        as a server, the host key is used to sign certain packets during the
        SSH2 negotiation, so that the client can trust that we are who we say
        we are.  Because this is used for signing, the key must contain private
        key info, not just the public half.
        
        @param key: the host key to add, usually an L{RSAKey <rsakey.RSAKey>} or
            L{DSSKey <dsskey.DSSKey>}.
        @type key: L{PKey <pkey.PKey>}
        """
        self.server_key_dict[key.get_name()] = key

    def get_server_key(self):
        """
        Return the active host key, in server mode.  After negotiating with the
        client, this method will return the negotiated host key.  If only one
        type of host key was set with L{add_server_key}, that's the only key
        that will ever be returned.  But in cases where you have set more than
        one type of host key (for example, an RSA key and a DSS key), the key
        type will be negotiated by the client, and this method will return the
        key of the type agreed on.  If the host key has not been negotiated
        yet, C{None} is returned.  In client mode, the behavior is undefined.

        @return: host key of the type negotiated by the client, or C{None}.
        @rtype: L{PKey <pkey.PKey>}
        """
        try:
            return self.server_key_dict[self.host_key_type]
        except KeyError:
            return None

    def load_server_moduli(filename=None):
        """
        I{(optional)}
        Load a file of prime moduli for use in doing group-exchange key
        negotiation in server mode.  It's a rather obscure option and can be
        safely ignored.

        In server mode, the remote client may request "group-exchange" key
        negotiation, which asks the server to send a random prime number that
        fits certain criteria.  These primes are pretty difficult to compute,
        so they can't be generated on demand.  But many systems contain a file
        of suitable primes (usually named something like C{/etc/ssh/moduli}).
        If you call C{load_server_moduli} and it returns C{True}, then this
        file of primes has been loaded and we will support "group-exchange" in
        server mode.  Otherwise server mode will just claim that it doesn't
        support that method of key negotiation.

        @param filename: optional path to the moduli file, if you happen to
            know that it's not in a standard location.
        @type filename: str
        @return: True if a moduli file was successfully loaded; False
            otherwise.
        @rtype: bool

        @since: doduo
        
        @note: This has no effect when used in client mode.
        """
        BaseTransport._modulus_pack = ModulusPack(randpool)
        # places to look for the openssh "moduli" file
        file_list = [ '/etc/ssh/moduli', '/usr/local/etc/moduli' ]
        if filename is not None:
            file_list.insert(0, filename)
        for fn in file_list:
            try:
                BaseTransport._modulus_pack.read_file(fn)
                return True
            except IOError:
                pass
        # none succeeded
        BaseTransport._modulus_pack = None
        return False
    load_server_moduli = staticmethod(load_server_moduli)

    def close(self):
        """
        Close this session, and any open channels that are tied to it.
        """
        self.active = False
        self.packetizer.close()
        for chan in self.channels.values():
            chan._unlink()

    def get_remote_server_key(self):
        """
        Return the host key of the server (in client mode).

        @note: Previously this call returned a tuple of (key type, key string).
            You can get the same effect by calling
            L{PKey.get_name <pkey.PKey.get_name>} for the key type, and
            C{str(key)} for the key string.

        @raise SSHException: if no session is currently active.
        
        @return: public key of the remote server.
        @rtype: L{PKey <pkey.PKey>}
        """
        if (not self.active) or (not self.initial_kex_done):
            raise SSHException('No existing session')
        return self.host_key

    def is_active(self):
        """
        Return true if this session is active (open).

        @return: True if the session is still active (open); False if the
            session is closed.
        @rtype: bool
        """
        return self.active

    def open_session(self):
        """
        Request a new channel to the server, of type C{"session"}.  This
        is just an alias for C{open_channel('session')}.

        @return: a new L{Channel} on success, or C{None} if the request is
            rejected or the session ends prematurely.
        @rtype: L{Channel}
        """
        return self.open_channel('session')

    def open_channel(self, kind, dest_addr=None, src_addr=None):
        """
        Request a new channel to the server.  L{Channel}s are socket-like
        objects used for the actual transfer of data across the session.
        You may only request a channel after negotiating encryption (using
        L{connect} or L{start_client}) and authenticating.

        @param kind: the kind of channel requested (usually C{"session"},
            C{"forwarded-tcpip"} or C{"direct-tcpip"}).
        @type kind: str
        @param dest_addr: the destination address of this port forwarding,
            if C{kind} is C{"forwarded-tcpip"} or C{"direct-tcpip"} (ignored
            for other channel types).
        @type dest_addr: (str, int)
        @param src_addr: the source address of this port forwarding, if
            C{kind} is C{"forwarded-tcpip"} or C{"direct-tcpip"}.
        @type src_addr: (str, int)
        @return: a new L{Channel} on success, or C{None} if the request is
            rejected or the session ends prematurely.
        @rtype: L{Channel}
        """
        chan = None
        if not self.active:
            # don't bother trying to allocate a channel
            return None
        self.lock.acquire()
        try:
            chanid = self.channel_counter
            while self.channels.has_key(chanid):
                self.channel_counter = (self.channel_counter + 1) & 0xffffff
                chanid = self.channel_counter
            self.channel_counter = (self.channel_counter + 1) & 0xffffff
            m = Message()
            m.add_byte(chr(MSG_CHANNEL_OPEN))
            m.add_string(kind)
            m.add_int(chanid)
            m.add_int(self.window_size)
            m.add_int(self.max_packet_size)
            if (kind == 'forwarded-tcpip') or (kind == 'direct-tcpip'):
                m.add_string(dest_addr[0])
                m.add_int(dest_addr[1])
                m.add_string(src_addr[0])
                m.add_int(src_addr[1])
            self.channels[chanid] = chan = Channel(chanid)
            self.channel_events[chanid] = event = threading.Event()
            chan._set_transport(self)
            chan._set_window(self.window_size, self.max_packet_size)
            self._send_user_message(m)
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

    def open_sftp_client(self):
        """
        Create an SFTP client channel from an open transport.  On success,
        an SFTP session will be opened with the remote host, and a new
        SFTPClient object will be returned.

        @return: a new L{SFTPClient} object, referring to an sftp session
            (channel) across this transport
        @rtype: L{SFTPClient}
        """
        return SFTPClient.from_transport(self)

    def send_ignore(self, bytes=None):
        """
        Send a junk packet across the encrypted link.  This is sometimes used
        to add "noise" to a connection to confuse would-be attackers.  It can
        also be used as a keep-alive for long lived connections traversing
        firewalls.

        @param bytes: the number of random bytes to send in the payload of the
        ignored packet -- defaults to a random number from 10 to 41.
        @type bytes: int

        @since: fearow
        """
        m = Message()
        m.add_byte(chr(MSG_IGNORE))
        if bytes is None:
            bytes = (ord(randpool.get_bytes(1)) % 32) + 10
        m.add_bytes(randpool.get_bytes(bytes))
        self._send_user_message(m)

    def renegotiate_keys(self):
        """
        Force this session to switch to new keys.  Normally this is done
        automatically after the session hits a certain number of packets or
        bytes sent or received, but this method gives you the option of forcing
        new keys whenever you want.  Negotiating new keys causes a pause in
        traffic both ways as the two sides swap keys and do computations.  This
        method returns when the session has switched to new keys, or the
        session has died mid-negotiation.

        @return: True if the renegotiation was successful, and the link is
            using new keys; False if the session dropped during renegotiation.
        @rtype: bool
        """
        self.completion_event = threading.Event()
        self._send_kex_init()
        while 1:
            self.completion_event.wait(0.1);
            if not self.active:
                return False
            if self.completion_event.isSet():
                break
        return True

    def set_keepalive(self, interval):
        """
        Turn on/off keepalive packets (default is off).  If this is set, after
        C{interval} seconds without sending any data over the connection, a
        "keepalive" packet will be sent (and ignored by the remote host).  This
        can be useful to keep connections alive over a NAT, for example.
        
        @param interval: seconds to wait before sending a keepalive packet (or
            0 to disable keepalives).
        @type interval: int

        @since: fearow
        """
        self.packetizer.set_keepalive(interval,
            lambda x=self: x.global_request('keepalive@lag.net', wait=False))

    def global_request(self, kind, data=None, wait=True):
        """
        Make a global request to the remote host.  These are normally
        extensions to the SSH2 protocol.

        @param kind: name of the request.
        @type kind: str
        @param data: an optional tuple containing additional data to attach
            to the request.
        @type data: tuple
        @param wait: C{True} if this method should not return until a response
            is received; C{False} otherwise.
        @type wait: bool
        @return: a L{Message} containing possible additional data if the
            request was successful (or an empty L{Message} if C{wait} was
            C{False}); C{None} if the request was denied.
        @rtype: L{Message}

        @since: fearow
        """
        if wait:
            self.completion_event = threading.Event()
        m = Message()
        m.add_byte(chr(MSG_GLOBAL_REQUEST))
        m.add_string(kind)
        m.add_boolean(wait)
        if data is not None:
            for item in data:
                m.add(item)
        self._log(DEBUG, 'Sending global request "%s"' % kind)
        self._send_user_message(m)
        if not wait:
            return None
        while True:
            self.completion_event.wait(0.1)
            if not self.active:
                return None
            if self.completion_event.isSet():
                break
        return self.global_response

    def accept(self, timeout=None):
        self.lock.acquire()
        try:
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

    def connect(self, hostkey=None, username='', password=None, pkey=None):
        """
        Negotiate an SSH2 session, and optionally verify the server's host key
        and authenticate using a password or private key.  This is a shortcut
        for L{start_client}, L{get_remote_server_key}, and
        L{Transport.auth_password} or L{Transport.auth_publickey}.  Use those
        methods if you want more control.

        You can use this method immediately after creating a Transport to
        negotiate encryption with a server.  If it fails, an exception will be
        thrown.  On success, the method will return cleanly, and an encrypted
        session exists.  You may immediately call L{open_channel} or
        L{open_session} to get a L{Channel} object, which is used for data
        transfer.

        @note: If you fail to supply a password or private key, this method may
        succeed, but a subsequent L{open_channel} or L{open_session} call may
        fail because you haven't authenticated yet.

        @param hostkey: the host key expected from the server, or C{None} if
            you don't want to do host key verification.
        @type hostkey: L{PKey<pkey.PKey>}
        @param username: the username to authenticate as.
        @type username: str
        @param password: a password to use for authentication, if you want to
            use password authentication; otherwise C{None}.
        @type password: str
        @param pkey: a private key to use for authentication, if you want to
            use private key authentication; otherwise C{None}.
        @type pkey: L{PKey<pkey.PKey>}
        
        @raise SSHException: if the SSH2 negotiation fails, the host key
            supplied by the server is incorrect, or authentication fails.

        @since: doduo
        """
        if hostkey is not None:
            self._preferred_keys = [ hostkey.get_name() ]

        event = threading.Event()
        self.start_client(event)
        while True:
            event.wait(0.1)
            if not self.active:
                e = self.get_exception()
                if e is not None:
                    raise e
                raise SSHException('Negotiation failed.')
            if event.isSet():
                break

        # check host key if we were given one
        if (hostkey is not None):
            key = self.get_remote_server_key()
            if (key.get_name() != hostkey.get_name()) or (str(key) != str(hostkey)):
                self._log(DEBUG, 'Bad host key from server')
                self._log(DEBUG, 'Expected: %s: %s' % (hostkey.get_name(), repr(str(hostkey))))
                self._log(DEBUG, 'Got     : %s: %s' % (key.get_name(), repr(str(key))))
                raise SSHException('Bad host key from server')
            self._log(DEBUG, 'Host key verified (%s)' % hostkey.get_name())

        if (pkey is not None) or (password is not None):
            if password is not None:
                self._log(DEBUG, 'Attempting password auth...')
                self.auth_password(username, password)
            else:
                self._log(DEBUG, 'Attempting public-key auth...')
                self.auth_publickey(username, pkey)

        return
        
    def get_exception(self):
        """
        Return any exception that happened during the last server request.
        This can be used to fetch more specific error information after using
        calls like L{start_client}.  The exception (if any) is cleared after
        this call.
        
        @return: an exception, or C{None} if there is no stored exception.
        @rtype: Exception
        
        @since: 1.1
        """
        self.lock.acquire()
        try:
            e = self.saved_exception
            self.saved_exception = None
            return e
        finally:
            self.lock.release()

    def set_subsystem_handler(self, name, handler, *larg, **kwarg):
        """
        Set the handler class for a subsystem in server mode.  If a request
        for this subsystem is made on an open ssh channel later, this handler
        will be constructed and called -- see L{SubsystemHandler} for more
        detailed documentation.

        Any extra parameters (including keyword arguments) are saved and
        passed to the L{SubsystemHandler} constructor later.

        @param name: name of the subsystem.
        @type name: str
        @param handler: subclass of L{SubsystemHandler} that handles this
            subsystem.
        @type handler: class
        """
        try:
            self.lock.acquire()
            self.subsystem_table[name] = (handler, larg, kwarg)
        finally:
            self.lock.release()

    def set_log_channel(self, name):
        """
        Set the channel for this transport's logging.  The default is
        C{"paramiko.transport"} but it can be set to anything you want.
        (See the C{logging} module for more info.)  SSH Channels will log
        to a sub-channel of the one specified.

        @param name: new channel name for logging.
        @type name: str

        @since: 1.1
        """
        self.log_name = name
        self.logger = util.get_logger(name)

    def get_log_channel(self):
        """
        Return the channel name used for this transport's logging.

        @return: channel name.
        @rtype: str

        @since: 1.2
        """
        return self.log_name

    def set_hexdump(self, hexdump):
        """
        Turn on/off logging a hex dump of protocol traffic at DEBUG level in
        the logs.  Normally you would want this off (which is the default),
        but if you are debugging something, it may be useful.

        @param hexdump: C{True} to log protocol traffix (in hex) to the log;
            C{False} otherwise.
        @type hexdump: bool
        """
        self.packetizer.set_hexdump(hexdump)
    
    def get_hexdump(self):
        """
        Return C{True} if the transport is currently logging hex dumps of
        protocol traffic.
        
        @return: C{True} if hex dumps are being logged
        @rtype: bool
        
        @since: 1.4
        """
        return self.packetizer.get_hexdump()

    def stop_thread(self):
        self.active = False
        self.packetizer.close()


    ###  internals...

    
    def _log(self, level, msg):
        if issubclass(type(msg), list):
            for m in msg:
                self.logger.log(level, m)
        else:
            self.logger.log(level, msg)

    def _get_modulus_pack(self):
        "used by KexGex to find primes for group exchange"
        return self._modulus_pack

    def _unlink_channel(self, chanid):
        "used by a Channel to remove itself from the active channel list"
        try:
            self.lock.acquire()
            if self.channels.has_key(chanid):
                del self.channels[chanid]
        finally:
            self.lock.release()

    def _send_message(self, data):
        self.packetizer.send_message(data)
        if self.packetizer.need_rekey() and not self.in_kex:
            self._send_kex_init()

    def _send_user_message(self, data):
        """
        send a message, but block if we're in key negotiation.  this is used
        for user-initiated requests.
        """
        while True:
            self.clear_to_send.wait(0.1)
            if not self.active:
                self._log(DEBUG, 'Dropping user packet because connection is dead.')
                return
            if self.clear_to_send.isSet():
                break
        self._send_message(data)

    def _set_K_H(self, k, h):
        "used by a kex object to set the K (root key) and H (exchange hash)"
        self.K = k
        self.H = h
        if self.session_id == None:
            self.session_id = h

    def _expect_packet(self, type):
        "used by a kex object to register the next packet type it expects to see"
        self.expected_packet = type

    def _verify_key(self, host_key, sig):
        key = self._key_info[self.host_key_type](Message(host_key))
        if key is None:
            raise SSHException('Unknown host key type')
        if not key.verify_ssh_sig(self.H, Message(sig)):
            raise SSHException('Signature verification (%s) failed.  Boo.  Robey should debug this.' % self.host_key_type)
        self.host_key = key

    def _compute_key(self, id, nbytes):
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

    def _get_cipher(self, name, key, iv):
        if not self._cipher_info.has_key(name):
            raise SSHException('Unknown client cipher ' + name)
        return self._cipher_info[name]['class'].new(key, self._cipher_info[name]['mode'], iv)

    def _run(self):
        # active=True occurs before the thread is launched, to avoid a race
        _active_threads.append(self)
        if self.server_mode:
            self._log(DEBUG, 'starting thread (server mode): %s' % hex(long(id(self)) & 0xffffffffL))
        else:
            self._log(DEBUG, 'starting thread (client mode): %s' % hex(long(id(self)) & 0xffffffffL))
        try:
            self.packetizer.write_all(self.local_version + '\r\n')
            self._check_banner()
            self._send_kex_init()
            self.expected_packet = MSG_KEXINIT

            while self.active:
                if self.packetizer.need_rekey() and not self.in_kex:
                    self._send_kex_init()
                ptype, m = self.packetizer.read_message()
                if ptype == MSG_IGNORE:
                    continue
                elif ptype == MSG_DISCONNECT:
                    self._parse_disconnect(m)
                    self.active = False
                    self.packetizer.close()
                    break
                elif ptype == MSG_DEBUG:
                    self._parse_debug(m)
                    continue
                if self.expected_packet != 0:
                    if ptype != self.expected_packet:
                        raise SSHException('Expecting packet %d, got %d' % (self.expected_packet, ptype))
                    self.expected_packet = 0
                    if (ptype >= 30) and (ptype <= 39):
                        self.kex_engine.parse_next(ptype, m)
                        continue

                if self._handler_table.has_key(ptype):
                    self._handler_table[ptype](self, m)
                elif self._channel_handler_table.has_key(ptype):
                    chanid = m.get_int()
                    if self.channels.has_key(chanid):
                        self._channel_handler_table[ptype](self.channels[chanid], m)
                    else:
                        self._log(ERROR, 'Channel request for unknown channel %d' % chanid)
                        self.active = False
                        self.packetizer.close()
                else:
                    self._log(WARNING, 'Oops, unhandled type %d' % ptype)
                    msg = Message()
                    msg.add_byte(chr(MSG_UNIMPLEMENTED))
                    msg.add_int(m.seqno)
                    self._send_message(msg)
        except SSHException, e:
            self._log(ERROR, 'Exception: ' + str(e))
            self._log(ERROR, util.tb_strings())
            self.saved_exception = e
        except EOFError, e:
            self._log(DEBUG, 'EOF in transport thread')
            #self._log(DEBUG, util.tb_strings())
            self.saved_exception = e
        except Exception, e:
            self._log(ERROR, 'Unknown exception: ' + str(e))
            self._log(ERROR, util.tb_strings())
            self.saved_exception = e
        _active_threads.remove(self)
        for chan in self.channels.values():
            chan._unlink()
        if self.active:
            self.active = False
            self.packetizer.close()
            if self.completion_event != None:
                self.completion_event.set()
            if self.auth_event != None:
                self.auth_event.set()
            for event in self.channel_events.values():
                event.set()
        self.sock.close()


    ###  protocol stages


    def _negotiate_keys(self, m):
        # throws SSHException on anything unusual
        self.clear_to_send.clear()
        if self.local_kex_init == None:
            # remote side wants to renegotiate
            self._send_kex_init()
        self._parse_kex_init(m)
        self.kex_engine.start_kex()

    def _check_banner(self):
        # this is slow, but we only have to do it once
        for i in range(5):
            # give them 5 seconds for the first line, then just 2 seconds each additional line
            if i == 0:
                timeout = 5
            else:
                timeout = 2
            try:
                buffer = self.packetizer.readline(timeout)
            except Exception, x:
                raise SSHException('Error reading SSH protocol banner' + str(x))
            if buffer[:4] == 'SSH-':
                break
            self._log(DEBUG, 'Banner: ' + buffer)
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
        self._log(INFO, 'Connected (version %s, client %s)' % (version, client))

    def _send_kex_init(self):
        """
        announce to the other side that we'd like to negotiate keys, and what
        kind of key negotiation we support.
        """
        self.clear_to_send.clear()
        self.in_kex = True
        if self.server_mode:
            if (self._modulus_pack is None) and ('diffie-hellman-group-exchange-sha1' in self._preferred_kex):
                # can't do group-exchange if we don't have a pack of potential primes
                pkex = list(self.get_security_options().kex)
                pkex.remove('diffie-hellman-group-exchange-sha1')
                self.get_security_options().kex = pkex
            available_server_keys = filter(self.server_key_dict.keys().__contains__,
                                           self._preferred_keys)
        else:
            available_server_keys = self._preferred_keys

        m = Message()
        m.add_byte(chr(MSG_KEXINIT))
        m.add_bytes(randpool.get_bytes(16))
        m.add(','.join(self._preferred_kex))
        m.add(','.join(available_server_keys))
        m.add(','.join(self._preferred_ciphers))
        m.add(','.join(self._preferred_ciphers))
        m.add(','.join(self._preferred_macs))
        m.add(','.join(self._preferred_macs))
        m.add('none')
        m.add('none')
        m.add('')
        m.add('')
        m.add_boolean(False)
        m.add_int(0)
        # save a copy for later (needed to compute a hash)
        self.local_kex_init = str(m)
        self._send_message(m)

    def _parse_kex_init(self, m):
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
            agreed_kex = filter(self._preferred_kex.__contains__, kex_algo_list)
        else:
            agreed_kex = filter(kex_algo_list.__contains__, self._preferred_kex)
        if len(agreed_kex) == 0:
            raise SSHException('Incompatible ssh peer (no acceptable kex algorithm)')
        self.kex_engine = self._kex_info[agreed_kex[0]](self)

        if self.server_mode:
            available_server_keys = filter(self.server_key_dict.keys().__contains__,
                                           self._preferred_keys)
            agreed_keys = filter(available_server_keys.__contains__, server_key_algo_list)
        else:
            agreed_keys = filter(server_key_algo_list.__contains__, self._preferred_keys)
        if len(agreed_keys) == 0:
            raise SSHException('Incompatible ssh peer (no acceptable host key)')
        self.host_key_type = agreed_keys[0]
        if self.server_mode and (self.get_server_key() is None):
            raise SSHException('Incompatible ssh peer (can\'t match requested host key type)')

        if self.server_mode:
            agreed_local_ciphers = filter(self._preferred_ciphers.__contains__,
                                           server_encrypt_algo_list)
            agreed_remote_ciphers = filter(self._preferred_ciphers.__contains__,
                                          client_encrypt_algo_list)
        else:
            agreed_local_ciphers = filter(client_encrypt_algo_list.__contains__,
                                          self._preferred_ciphers)
            agreed_remote_ciphers = filter(server_encrypt_algo_list.__contains__,
                                           self._preferred_ciphers)
        if (len(agreed_local_ciphers) == 0) or (len(agreed_remote_ciphers) == 0):
            raise SSHException('Incompatible ssh server (no acceptable ciphers)')
        self.local_cipher = agreed_local_ciphers[0]
        self.remote_cipher = agreed_remote_ciphers[0]
        self._log(DEBUG, 'Ciphers agreed: local=%s, remote=%s' % (self.local_cipher, self.remote_cipher))

        if self.server_mode:
            agreed_remote_macs = filter(self._preferred_macs.__contains__, client_mac_algo_list)
            agreed_local_macs = filter(self._preferred_macs.__contains__, server_mac_algo_list)
        else:
            agreed_local_macs = filter(client_mac_algo_list.__contains__, self._preferred_macs)
            agreed_remote_macs = filter(server_mac_algo_list.__contains__, self._preferred_macs)
        if (len(agreed_local_macs) == 0) or (len(agreed_remote_macs) == 0):
            raise SSHException('Incompatible ssh server (no acceptable macs)')
        self.local_mac = agreed_local_macs[0]
        self.remote_mac = agreed_remote_macs[0]

        self._log(DEBUG, 'kex algos:' + str(kex_algo_list) + ' server key:' + str(server_key_algo_list) + \
                  ' client encrypt:' + str(client_encrypt_algo_list) + \
                  ' server encrypt:' + str(server_encrypt_algo_list) + \
                  ' client mac:' + str(client_mac_algo_list) + \
                  ' server mac:' + str(server_mac_algo_list) + \
                  ' client compress:' + str(client_compress_algo_list) + \
                  ' server compress:' + str(server_compress_algo_list) + \
                  ' client lang:' + str(client_lang_list) + \
                  ' server lang:' + str(server_lang_list) + \
                  ' kex follows?' + str(kex_follows))
        self._log(DEBUG, 'using kex %s; server key type %s; cipher: local %s, remote %s; mac: local %s, remote %s' %
                  (agreed_kex[0], self.host_key_type, self.local_cipher, self.remote_cipher, self.local_mac,
                   self.remote_mac))

        # save for computing hash later...
        # now wait!  openssh has a bug (and others might too) where there are
        # actually some extra bytes (one NUL byte in openssh's case) added to
        # the end of the packet but not parsed.  turns out we need to throw
        # away those bytes because they aren't part of the hash.
        self.remote_kex_init = chr(MSG_KEXINIT) + m.get_so_far()

    def _activate_inbound(self):
        "switch on newly negotiated encryption parameters for inbound traffic"
        block_size = self._cipher_info[self.remote_cipher]['block-size']
        if self.server_mode:
            IV_in = self._compute_key('A', block_size)
            key_in = self._compute_key('C', self._cipher_info[self.remote_cipher]['key-size'])
        else:
            IV_in = self._compute_key('B', block_size)
            key_in = self._compute_key('D', self._cipher_info[self.remote_cipher]['key-size'])
        engine = self._get_cipher(self.remote_cipher, key_in, IV_in)
        mac_size = self._mac_info[self.remote_mac]['size']
        mac_engine = self._mac_info[self.remote_mac]['class']
        # initial mac keys are done in the hash's natural size (not the potentially truncated
        # transmission size)
        if self.server_mode:
            mac_key = self._compute_key('E', mac_engine.digest_size)
        else:
            mac_key = self._compute_key('F', mac_engine.digest_size)
        self.packetizer.set_inbound_cipher(engine, block_size, mac_engine, mac_size, mac_key)

    def _activate_outbound(self):
        "switch on newly negotiated encryption parameters for outbound traffic"
        m = Message()
        m.add_byte(chr(MSG_NEWKEYS))
        self._send_message(m)
        block_size = self._cipher_info[self.local_cipher]['block-size']
        if self.server_mode:
            IV_out = self._compute_key('B', block_size)
            key_out = self._compute_key('D', self._cipher_info[self.local_cipher]['key-size'])
        else:
            IV_out = self._compute_key('A', block_size)
            key_out = self._compute_key('C', self._cipher_info[self.local_cipher]['key-size'])
        engine = self._get_cipher(self.local_cipher, key_out, IV_out)
        mac_size = self._mac_info[self.local_mac]['size']
        mac_engine = self._mac_info[self.local_mac]['class']
        # initial mac keys are done in the hash's natural size (not the potentially truncated
        # transmission size)
        if self.server_mode:
            mac_key = self._compute_key('F', mac_engine.digest_size)
        else:
            mac_key = self._compute_key('E', mac_engine.digest_size)
        self.packetizer.set_outbound_cipher(engine, block_size, mac_engine, mac_size, mac_key)
        if not self.packetizer.need_rekey():
            self.in_kex = False
        # we always expect to receive NEWKEYS now
        self.expected_packet = MSG_NEWKEYS

    def _parse_newkeys(self, m):
        self._log(DEBUG, 'Switch to new keys ...')
        self._activate_inbound()
        # can also free a bunch of stuff here
        self.local_kex_init = self.remote_kex_init = None
        self.K = None
        if not self.initial_kex_done:
            # this was the first key exchange
            self.initial_kex_done = True
        # send an event?
        if self.completion_event != None:
            self.completion_event.set()
        # it's now okay to send data again (if this was a re-key)
        if not self.packetizer.need_rekey():
            self.in_kex = False
        self.clear_to_send.set()
        return

    def _parse_disconnect(self, m):
        code = m.get_int()
        desc = m.get_string()
        self._log(INFO, 'Disconnect (code %d): %s' % (code, desc))

    def _parse_global_request(self, m):
        kind = m.get_string()
        self._log(DEBUG, 'Received global request "%s"' % kind)
        want_reply = m.get_boolean()
        ok = self.server_object.check_global_request(kind, m)
        extra = ()
        if type(ok) is tuple:
            extra = ok
            ok = True
        if want_reply:
            msg = Message()
            if ok:
                msg.add_byte(chr(MSG_REQUEST_SUCCESS))
                for item in extra:
                    msg.add(item)
            else:
                msg.add_byte(chr(MSG_REQUEST_FAILURE))
            self._send_message(msg)

    def _parse_request_success(self, m):
        self._log(DEBUG, 'Global request successful.')
        self.global_response = m
        if self.completion_event is not None:
            self.completion_event.set()
        
    def _parse_request_failure(self, m):
        self._log(DEBUG, 'Global request denied.')
        self.global_response = None
        if self.completion_event is not None:
            self.completion_event.set()

    def _parse_channel_open_success(self, m):
        chanid = m.get_int()
        server_chanid = m.get_int()
        server_window_size = m.get_int()
        server_max_packet_size = m.get_int()
        if not self.channels.has_key(chanid):
            self._log(WARNING, 'Success for unrequested channel! [??]')
            return
        self.lock.acquire()
        try:
            chan = self.channels[chanid]
            chan._set_remote_channel(server_chanid, server_window_size, server_max_packet_size)
            self._log(INFO, 'Secsh channel %d opened.' % chanid)
            if self.channel_events.has_key(chanid):
                self.channel_events[chanid].set()
                del self.channel_events[chanid]
        finally:
            self.lock.release()
        return

    def _parse_channel_open_failure(self, m):
        chanid = m.get_int()
        reason = m.get_int()
        reason_str = m.get_string()
        lang = m.get_string()
        if CONNECTION_FAILED_CODE.has_key(reason):
            reason_text = CONNECTION_FAILED_CODE[reason]
        else:
            reason_text = '(unknown code)'
        self._log(INFO, 'Secsh channel %d open FAILED: %s: %s' % (chanid, reason_str, reason_text))
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

    def _parse_channel_open(self, m):
        kind = m.get_string()
        chanid = m.get_int()
        initial_window_size = m.get_int()
        max_packet_size = m.get_int()
        reject = False
        if not self.server_mode:
            self._log(DEBUG, 'Rejecting "%s" channel request from server.' % kind)
            reject = True
            reason = OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        else:
            self.lock.acquire()
            try:
                my_chanid = self.channel_counter
                while self.channels.has_key(my_chanid):
                    self.channel_counter = (self.channel_counter + 1) & 0xffffff
                    my_chanid = self.channel_counter
                self.channel_counter = (self.channel_counter + 1) & 0xffffff
            finally:
                self.lock.release()
            reason = self.server_object.check_channel_request(kind, my_chanid) 
            if reason != OPEN_SUCCEEDED:
                self._log(DEBUG, 'Rejecting "%s" channel request from client.' % kind)
                reject = True
        if reject:
            msg = Message()
            msg.add_byte(chr(MSG_CHANNEL_OPEN_FAILURE))
            msg.add_int(chanid)
            msg.add_int(reason)
            msg.add_string('')
            msg.add_string('en')
            self._send_message(msg)
            return
        chan = Channel(my_chanid)
        try:
            self.lock.acquire()
            self.channels[my_chanid] = chan
            chan._set_transport(self)
            chan._set_window(self.window_size, self.max_packet_size)
            chan._set_remote_channel(chanid, initial_window_size, max_packet_size)
        finally:
            self.lock.release()
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_OPEN_SUCCESS))
        m.add_int(chanid)
        m.add_int(my_chanid)
        m.add_int(self.window_size)
        m.add_int(self.max_packet_size)
        self._send_message(m)
        self._log(INFO, 'Secsh channel %d opened.' % my_chanid)
        try:
            self.lock.acquire()
            self.server_accepts.append(chan)
            self.server_accept_cv.notify()
        finally:
            self.lock.release()

    def _parse_debug(self, m):
        always_display = m.get_boolean()
        msg = m.get_string()
        lang = m.get_string()
        self._log(DEBUG, 'Debug msg: ' + util.safe_string(msg))

    def _get_subsystem_handler(self, name):
        try:
            self.lock.acquire()
            if not self.subsystem_table.has_key(name):
                return (None, [], {})
            return self.subsystem_table[name]
        finally:
            self.lock.release()

    _handler_table = {
        MSG_NEWKEYS: _parse_newkeys,
        MSG_GLOBAL_REQUEST: _parse_global_request,
        MSG_REQUEST_SUCCESS: _parse_request_success,
        MSG_REQUEST_FAILURE: _parse_request_failure,
        MSG_CHANNEL_OPEN_SUCCESS: _parse_channel_open_success,
        MSG_CHANNEL_OPEN_FAILURE: _parse_channel_open_failure,
        MSG_CHANNEL_OPEN: _parse_channel_open,
        MSG_KEXINIT: _negotiate_keys,
        }

    _channel_handler_table = {
        MSG_CHANNEL_SUCCESS: Channel._request_success,
        MSG_CHANNEL_FAILURE: Channel._request_failed,
        MSG_CHANNEL_DATA: Channel._feed,
        MSG_CHANNEL_EXTENDED_DATA: Channel._feed_extended,
        MSG_CHANNEL_WINDOW_ADJUST: Channel._window_adjust,
        MSG_CHANNEL_REQUEST: Channel._handle_request,
        MSG_CHANNEL_EOF: Channel._handle_eof,
        MSG_CHANNEL_CLOSE: Channel._handle_close,
        }

from server import ServerInterface
