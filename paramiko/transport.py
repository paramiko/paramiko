# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Core protocol implementation
"""

import os
import socket
import sys
import threading
import time
import weakref
from hashlib import md5, sha1, sha256, sha512

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    algorithms,
    Cipher,
    modes,
    aead,
)

import paramiko
from paramiko import util
from paramiko.auth_handler import AuthHandler, AuthOnlyHandler
from paramiko.ssh_gss import GSSAuth
from paramiko.channel import Channel
from paramiko.common import (
    xffffffff,
    cMSG_CHANNEL_OPEN,
    cMSG_IGNORE,
    cMSG_GLOBAL_REQUEST,
    DEBUG,
    MSG_KEXINIT,
    MSG_IGNORE,
    MSG_DISCONNECT,
    MSG_DEBUG,
    ERROR,
    WARNING,
    cMSG_UNIMPLEMENTED,
    INFO,
    cMSG_KEXINIT,
    cMSG_NEWKEYS,
    MSG_NEWKEYS,
    cMSG_REQUEST_SUCCESS,
    cMSG_REQUEST_FAILURE,
    CONNECTION_FAILED_CODE,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
    cMSG_CHANNEL_OPEN_FAILURE,
    cMSG_CHANNEL_OPEN_SUCCESS,
    MSG_GLOBAL_REQUEST,
    MSG_REQUEST_SUCCESS,
    MSG_REQUEST_FAILURE,
    cMSG_SERVICE_REQUEST,
    MSG_SERVICE_ACCEPT,
    MSG_CHANNEL_OPEN_SUCCESS,
    MSG_CHANNEL_OPEN_FAILURE,
    MSG_CHANNEL_OPEN,
    MSG_CHANNEL_SUCCESS,
    MSG_CHANNEL_FAILURE,
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_EXTENDED_DATA,
    MSG_CHANNEL_WINDOW_ADJUST,
    MSG_CHANNEL_REQUEST,
    MSG_CHANNEL_EOF,
    MSG_CHANNEL_CLOSE,
    MIN_WINDOW_SIZE,
    MIN_PACKET_SIZE,
    MAX_WINDOW_SIZE,
    DEFAULT_WINDOW_SIZE,
    DEFAULT_MAX_PACKET_SIZE,
    HIGHEST_USERAUTH_MESSAGE_ID,
    MSG_UNIMPLEMENTED,
    MSG_NAMES,
    MSG_EXT_INFO,
    cMSG_EXT_INFO,
    byte_ord,
)
from paramiko.compress import ZlibCompressor, ZlibDecompressor
from paramiko.ed25519key import Ed25519Key
from paramiko.kex_curve25519 import KexCurve25519
from paramiko.kex_gex import KexGex, KexGexSHA256
from paramiko.kex_group1 import KexGroup1
from paramiko.kex_group14 import KexGroup14, KexGroup14SHA256
from paramiko.kex_group16 import KexGroup16SHA512
from paramiko.kex_ecdh_nist import KexNistp256, KexNistp384, KexNistp521
from paramiko.kex_gss import KexGSSGex, KexGSSGroup1, KexGSSGroup14
from paramiko.message import Message
from paramiko.packet import Packetizer, NeedRekeyException
from paramiko.primes import ModulusPack
from paramiko.rsakey import RSAKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.server import ServerInterface
from paramiko.sftp_client import SFTPClient
from paramiko.ssh_exception import (
    BadAuthenticationType,
    ChannelException,
    IncompatiblePeer,
    MessageOrderError,
    ProxyCommandFailure,
    SSHException,
)
from paramiko.util import (
    ClosingContextManager,
    clamp_value,
    b,
)


# TripleDES is moving from `cryptography.hazmat.primitives.ciphers.algorithms`
# in cryptography>=43.0.0 to `cryptography.hazmat.decrepit.ciphers.algorithms`
# It will be removed from `cryptography.hazmat.primitives.ciphers.algorithms`
# in cryptography==48.0.0.
#
# Source References:
# - https://github.com/pyca/cryptography/commit/722a6393e61b3ac
# - https://github.com/pyca/cryptography/pull/11407/files
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


# for thread cleanup
_active_threads = []


def _join_lingering_threads():
    for thr in _active_threads:
        thr.stop_thread()


import atexit

atexit.register(_join_lingering_threads)


class Transport(threading.Thread, ClosingContextManager):
    """
    An SSH Transport attaches to a stream (usually a socket), negotiates an
    encrypted session, authenticates, and then creates stream tunnels, called
    `channels <.Channel>`, across the session.  Multiple channels can be
    multiplexed across a single session (and often are, in the case of port
    forwardings).

    Instances of this class may be used as context managers.
    """

    _ENCRYPT = object()
    _DECRYPT = object()

    _PROTO_ID = "2.0"
    _CLIENT_ID = "paramiko_{}".format(paramiko.__version__)

    # These tuples of algorithm identifiers are in preference order; do not
    # reorder without reason!
    # NOTE: if you need to modify these, we suggest leveraging the
    # `disabled_algorithms` constructor argument (also available in SSHClient)
    # instead of monkeypatching or subclassing.
    _preferred_ciphers = (
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "3des-cbc",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )
    _preferred_macs = (
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1",
        "hmac-md5",
        "hmac-sha1-96",
        "hmac-md5-96",
    )
    # ~= HostKeyAlgorithms in OpenSSH land
    _preferred_keys = (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
    )
    # ~= PubKeyAcceptedAlgorithms
    _preferred_pubkeys = (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
    )
    _preferred_kex = (
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
    )
    if KexCurve25519.is_available():
        _preferred_kex = ("curve25519-sha256@libssh.org",) + _preferred_kex
    _preferred_gsskex = (
        "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
        "gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==",
        "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",
    )
    _preferred_compression = ("none",)

    _cipher_info = {
        "aes128-ctr": {
            "class": algorithms.AES,
            "mode": modes.CTR,
            "block-size": 16,
            "key-size": 16,
        },
        "aes192-ctr": {
            "class": algorithms.AES,
            "mode": modes.CTR,
            "block-size": 16,
            "key-size": 24,
        },
        "aes256-ctr": {
            "class": algorithms.AES,
            "mode": modes.CTR,
            "block-size": 16,
            "key-size": 32,
        },
        "aes128-cbc": {
            "class": algorithms.AES,
            "mode": modes.CBC,
            "block-size": 16,
            "key-size": 16,
        },
        "aes192-cbc": {
            "class": algorithms.AES,
            "mode": modes.CBC,
            "block-size": 16,
            "key-size": 24,
        },
        "aes256-cbc": {
            "class": algorithms.AES,
            "mode": modes.CBC,
            "block-size": 16,
            "key-size": 32,
        },
        "3des-cbc": {
            "class": TripleDES,
            "mode": modes.CBC,
            "block-size": 8,
            "key-size": 24,
        },
        "aes128-gcm@openssh.com": {
            "class": aead.AESGCM,
            "block-size": 16,
            "iv-size": 12,
            "key-size": 16,
            "is_aead": True,
        },
        "aes256-gcm@openssh.com": {
            "class": aead.AESGCM,
            "block-size": 16,
            "iv-size": 12,
            "key-size": 32,
            "is_aead": True,
        },
    }

    _mac_info = {
        "hmac-sha1": {"class": sha1, "size": 20},
        "hmac-sha1-96": {"class": sha1, "size": 12},
        "hmac-sha2-256": {"class": sha256, "size": 32},
        "hmac-sha2-256-etm@openssh.com": {"class": sha256, "size": 32},
        "hmac-sha2-512": {"class": sha512, "size": 64},
        "hmac-sha2-512-etm@openssh.com": {"class": sha512, "size": 64},
        "hmac-md5": {"class": md5, "size": 16},
        "hmac-md5-96": {"class": md5, "size": 12},
    }

    _key_info = {
        # TODO: at some point we will want to drop this as it's no longer
        # considered secure due to using SHA-1 for signatures. OpenSSH 8.8 no
        # longer supports it. Question becomes at what point do we want to
        # prevent users with older setups from using this?
        "ssh-rsa": RSAKey,
        "ssh-rsa-cert-v01@openssh.com": RSAKey,
        "rsa-sha2-256": RSAKey,
        "rsa-sha2-256-cert-v01@openssh.com": RSAKey,
        "rsa-sha2-512": RSAKey,
        "rsa-sha2-512-cert-v01@openssh.com": RSAKey,
        "ecdsa-sha2-nistp256": ECDSAKey,
        "ecdsa-sha2-nistp256-cert-v01@openssh.com": ECDSAKey,
        "ecdsa-sha2-nistp384": ECDSAKey,
        "ecdsa-sha2-nistp384-cert-v01@openssh.com": ECDSAKey,
        "ecdsa-sha2-nistp521": ECDSAKey,
        "ecdsa-sha2-nistp521-cert-v01@openssh.com": ECDSAKey,
        "ssh-ed25519": Ed25519Key,
        "ssh-ed25519-cert-v01@openssh.com": Ed25519Key,
    }

    _kex_info = {
        "diffie-hellman-group1-sha1": KexGroup1,
        "diffie-hellman-group14-sha1": KexGroup14,
        "diffie-hellman-group-exchange-sha1": KexGex,
        "diffie-hellman-group-exchange-sha256": KexGexSHA256,
        "diffie-hellman-group14-sha256": KexGroup14SHA256,
        "diffie-hellman-group16-sha512": KexGroup16SHA512,
        "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==": KexGSSGroup1,
        "gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==": KexGSSGroup14,
        "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==": KexGSSGex,
        "ecdh-sha2-nistp256": KexNistp256,
        "ecdh-sha2-nistp384": KexNistp384,
        "ecdh-sha2-nistp521": KexNistp521,
    }
    if KexCurve25519.is_available():
        _kex_info["curve25519-sha256@libssh.org"] = KexCurve25519

    _compression_info = {
        # zlib@openssh.com is just zlib, but only turned on after a successful
        # authentication.  openssh servers may only offer this type because
        # they've had troubles with security holes in zlib in the past.
        "zlib@openssh.com": (ZlibCompressor, ZlibDecompressor),
        "zlib": (ZlibCompressor, ZlibDecompressor),
        "none": (None, None),
    }

    _modulus_pack = None
    _active_check_timeout = 0.1

    def __init__(
        self,
        sock,
        default_window_size=DEFAULT_WINDOW_SIZE,
        default_max_packet_size=DEFAULT_MAX_PACKET_SIZE,
        gss_kex=False,
        gss_deleg_creds=True,
        disabled_algorithms=None,
        server_sig_algs=True,
        strict_kex=True,
        packetizer_class=None,
    ):
        """
        Create a new SSH session over an existing socket, or socket-like
        object.  This only creates the `.Transport` object; it doesn't begin
        the SSH session yet.  Use `connect` or `start_client` to begin a client
        session, or `start_server` to begin a server session.

        If the object is not actually a socket, it must have the following
        methods:

        - ``send(bytes)``: Writes from 1 to ``len(bytes)`` bytes, and returns
          an int representing the number of bytes written.  Returns
          0 or raises ``EOFError`` if the stream has been closed.
        - ``recv(int)``: Reads from 1 to ``int`` bytes and returns them as a
          string.  Returns 0 or raises ``EOFError`` if the stream has been
          closed.
        - ``close()``: Closes the socket.
        - ``settimeout(n)``: Sets a (float) timeout on I/O operations.

        For ease of use, you may also pass in an address (as a tuple) or a host
        string as the ``sock`` argument.  (A host string is a hostname with an
        optional port (separated by ``":"``) which will be converted into a
        tuple of ``(hostname, port)``.)  A socket will be connected to this
        address and used for communication.  Exceptions from the ``socket``
        call may be thrown in this case.

        .. note::
            Modifying the the window and packet sizes might have adverse
            effects on your channels created from this transport. The default
            values are the same as in the OpenSSH code base and have been
            battle tested.

        :param socket sock:
            a socket or socket-like object to create the session over.
        :param int default_window_size:
            sets the default window size on the transport. (defaults to
            2097152)
        :param int default_max_packet_size:
            sets the default max packet size on the transport. (defaults to
            32768)
        :param bool gss_kex:
            Whether to enable GSSAPI key exchange when GSSAPI is in play.
            Default: ``False``.
        :param bool gss_deleg_creds:
            Whether to enable GSSAPI credential delegation when GSSAPI is in
            play. Default: ``True``.
        :param dict disabled_algorithms:
            If given, must be a dictionary mapping algorithm type to an
            iterable of algorithm identifiers, which will be disabled for the
            lifetime of the transport.

            Keys should match the last word in the class' builtin algorithm
            tuple attributes, such as ``"ciphers"`` to disable names within
            ``_preferred_ciphers``; or ``"kex"`` to disable something defined
            inside ``_preferred_kex``. Values should exactly match members of
            the matching attribute.

            For example, if you need to disable
            ``diffie-hellman-group16-sha512`` key exchange (perhaps because
            your code talks to a server which implements it differently from
            Paramiko), specify ``disabled_algorithms={"kex":
            ["diffie-hellman-group16-sha512"]}``.
        :param bool server_sig_algs:
            Whether to send an extra message to compatible clients, in server
            mode, with a list of supported pubkey algorithms. Default:
            ``True``.
        :param bool strict_kex:
            Whether to advertise (and implement, if client also advertises
            support for) a "strict kex" mode for safer handshaking. Default:
            ``True``.
        :param packetizer_class:
            Which class to use for instantiating the internal packet handler.
            Default: ``None`` (i.e.: use `Packetizer` as normal).

        .. versionchanged:: 1.15
            Added the ``default_window_size`` and ``default_max_packet_size``
            arguments.
        .. versionchanged:: 1.15
            Added the ``gss_kex`` and ``gss_deleg_creds`` kwargs.
        .. versionchanged:: 2.6
            Added the ``disabled_algorithms`` kwarg.
        .. versionchanged:: 2.9
            Added the ``server_sig_algs`` kwarg.
        .. versionchanged:: 3.4
            Added the ``strict_kex`` kwarg.
        .. versionchanged:: 3.4
            Added the ``packetizer_class`` kwarg.
        """
        self.active = False
        self.hostname = None
        self.server_extensions = {}
        self.advertise_strict_kex = strict_kex
        self.agreed_on_strict_kex = False

        # TODO: these two overrides on sock's type should go away sometime, too
        # many ways to do it!
        if isinstance(sock, str):
            # convert "host:port" into (host, port)
            hl = sock.split(":", 1)
            self.hostname = hl[0]
            if len(hl) == 1:
                sock = (hl[0], 22)
            else:
                sock = (hl[0], int(hl[1]))
        if type(sock) is tuple:
            # connect to the given (host, port)
            hostname, port = sock
            self.hostname = hostname
            reason = "No suitable address family"
            addrinfos = socket.getaddrinfo(
                hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            for family, socktype, proto, canonname, sockaddr in addrinfos:
                if socktype == socket.SOCK_STREAM:
                    af = family
                    # addr = sockaddr
                    sock = socket.socket(af, socket.SOCK_STREAM)
                    try:
                        sock.connect((hostname, port))
                    except socket.error as e:
                        reason = str(e)
                    else:
                        break
            else:
                raise SSHException(
                    "Unable to connect to {}: {}".format(hostname, reason)
                )
        # okay, normal socket-ish flow here...
        threading.Thread.__init__(self)
        self.daemon = True
        self.sock = sock
        # we set the timeout so we can check self.active periodically to
        # see if we should bail. socket.timeout exception is never propagated.
        self.sock.settimeout(self._active_check_timeout)

        # negotiated crypto parameters
        self.packetizer = (packetizer_class or Packetizer)(sock)
        self.local_version = "SSH-" + self._PROTO_ID + "-" + self._CLIENT_ID
        self.remote_version = ""
        self.local_cipher = self.remote_cipher = ""
        self.local_kex_init = self.remote_kex_init = None
        self.local_mac = self.remote_mac = None
        self.local_compression = self.remote_compression = None
        self.session_id = None
        self.host_key_type = None
        self.host_key = None

        # GSS-API / SSPI Key Exchange
        self.use_gss_kex = gss_kex
        # This will be set to True if GSS-API Key Exchange was performed
        self.gss_kex_used = False
        self.kexgss_ctxt = None
        self.gss_host = None
        if self.use_gss_kex:
            self.kexgss_ctxt = GSSAuth("gssapi-keyex", gss_deleg_creds)
            self._preferred_kex = self._preferred_gsskex + self._preferred_kex

        # state used during negotiation
        self.kex_engine = None
        self.H = None
        self.K = None

        self.initial_kex_done = False
        self.in_kex = False
        self.authenticated = False
        self._expected_packet = tuple()
        # synchronization (always higher level than write_lock)
        self.lock = threading.Lock()

        # tracking open channels
        self._channels = ChannelMap()
        self.channel_events = {}  # (id -> Event)
        self.channels_seen = {}  # (id -> True)
        self._channel_counter = 0
        self.default_max_packet_size = default_max_packet_size
        self.default_window_size = default_window_size
        self._forward_agent_handler = None
        self._x11_handler = None
        self._tcp_handler = None

        self.saved_exception = None
        self.clear_to_send = threading.Event()
        self.clear_to_send_lock = threading.Lock()
        self.clear_to_send_timeout = 30.0
        self.log_name = "paramiko.transport"
        self.logger = util.get_logger(self.log_name)
        self.packetizer.set_log(self.logger)
        self.auth_handler = None
        # response Message from an arbitrary global request
        self.global_response = None
        # user-defined event callbacks
        self.completion_event = None
        # how long (seconds) to wait for the SSH banner
        self.banner_timeout = 15
        # how long (seconds) to wait for the handshake to finish after SSH
        # banner sent.
        self.handshake_timeout = 15
        # how long (seconds) to wait for the auth response.
        self.auth_timeout = 30
        # how long (seconds) to wait for opening a channel
        self.channel_timeout = 60 * 60
        self.disabled_algorithms = disabled_algorithms or {}
        self.server_sig_algs = server_sig_algs

        # server mode:
        self.server_mode = False
        self.server_object = None
        self.server_key_dict = {}
        self.server_accepts = []
        self.server_accept_cv = threading.Condition(self.lock)
        self.subsystem_table = {}

        # Handler table, now set at init time for easier per-instance
        # manipulation and subclass twiddling.
        self._handler_table = {
            MSG_EXT_INFO: self._parse_ext_info,
            MSG_NEWKEYS: self._parse_newkeys,
            MSG_GLOBAL_REQUEST: self._parse_global_request,
            MSG_REQUEST_SUCCESS: self._parse_request_success,
            MSG_REQUEST_FAILURE: self._parse_request_failure,
            MSG_CHANNEL_OPEN_SUCCESS: self._parse_channel_open_success,
            MSG_CHANNEL_OPEN_FAILURE: self._parse_channel_open_failure,
            MSG_CHANNEL_OPEN: self._parse_channel_open,
            MSG_KEXINIT: self._negotiate_keys,
        }

    def _filter_algorithm(self, type_):
        default = getattr(self, "_preferred_{}".format(type_))
        return tuple(
            x
            for x in default
            if x not in self.disabled_algorithms.get(type_, [])
        )

    @property
    def preferred_ciphers(self):
        return self._filter_algorithm("ciphers")

    @property
    def preferred_macs(self):
        return self._filter_algorithm("macs")

    @property
    def preferred_keys(self):
        # Interleave cert variants here; resistant to various background
        # overwriting of _preferred_keys, and necessary as hostkeys can't use
        # the logic pubkey auth does re: injecting/checking for certs at
        # runtime
        filtered = self._filter_algorithm("keys")
        return tuple(
            filtered
            + tuple("{}-cert-v01@openssh.com".format(x) for x in filtered)
        )

    @property
    def preferred_pubkeys(self):
        return self._filter_algorithm("pubkeys")

    @property
    def preferred_kex(self):
        return self._filter_algorithm("kex")

    @property
    def preferred_compression(self):
        return self._filter_algorithm("compression")

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.
        """
        id_ = hex(id(self) & xffffffff)
        out = "<paramiko.Transport at {}".format(id_)
        if not self.active:
            out += " (unconnected)"
        else:
            if self.local_cipher != "":
                out += " (cipher {}, {:d} bits)".format(
                    self.local_cipher,
                    self._cipher_info[self.local_cipher]["key-size"] * 8,
                )
            if self.is_authenticated():
                out += " (active; {} open channel(s))".format(
                    len(self._channels)
                )
            elif self.initial_kex_done:
                out += " (connected; awaiting auth)"
            else:
                out += " (connecting)"
        out += ">"
        return out

    def atfork(self):
        """
        Terminate this Transport without closing the session.  On posix
        systems, if a Transport is open during process forking, both parent
        and child will share the underlying socket, but only one process can
        use the connection (without corrupting the session).  Use this method
        to clean up a Transport object without disrupting the other process.

        .. versionadded:: 1.5.3
        """
        self.sock.close()
        self.close()

    def get_security_options(self):
        """
        Return a `.SecurityOptions` object which can be used to tweak the
        encryption algorithms this transport will permit (for encryption,
        digest/hash operations, public keys, and key exchanges) and the order
        of preference for them.
        """
        return SecurityOptions(self)

    def set_gss_host(self, gss_host, trust_dns=True, gssapi_requested=True):
        """
        Normalize/canonicalize ``self.gss_host`` depending on various factors.

        :param str gss_host:
            The explicitly requested GSS-oriented hostname to connect to (i.e.
            what the host's name is in the Kerberos database.) Defaults to
            ``self.hostname`` (which will be the 'real' target hostname and/or
            host portion of given socket object.)
        :param bool trust_dns:
            Indicates whether or not DNS is trusted; if true, DNS will be used
            to canonicalize the GSS hostname (which again will either be
            ``gss_host`` or the transport's default hostname.)
            (Defaults to True due to backwards compatibility.)
        :param bool gssapi_requested:
            Whether GSSAPI key exchange or authentication was even requested.
            If not, this is a no-op and nothing happens
            (and ``self.gss_host`` is not set.)
            (Defaults to True due to backwards compatibility.)
        :returns: ``None``.
        """
        # No GSSAPI in play == nothing to do
        if not gssapi_requested:
            return
        # Obtain the correct host first - did user request a GSS-specific name
        # to use that is distinct from the actual SSH target hostname?
        if gss_host is None:
            gss_host = self.hostname
        # Finally, canonicalize via DNS if DNS is trusted.
        if trust_dns and gss_host is not None:
            gss_host = socket.getfqdn(gss_host)
        # And set attribute for reference later.
        self.gss_host = gss_host

    def start_client(self, event=None, timeout=None):
        """
        Negotiate a new SSH2 session as a client.  This is the first step after
        creating a new `.Transport`.  A separate thread is created for protocol
        negotiation.

        If an event is passed in, this method returns immediately.  When
        negotiation is done (successful or not), the given ``Event`` will
        be triggered.  On failure, `is_active` will return ``False``.

        (Since 1.4) If ``event`` is ``None``, this method will not return until
        negotiation is done.  On success, the method returns normally.
        Otherwise an SSHException is raised.

        After a successful negotiation, you will usually want to authenticate,
        calling `auth_password <Transport.auth_password>` or
        `auth_publickey <Transport.auth_publickey>`.

        .. note:: `connect` is a simpler method for connecting as a client.

        .. note::
            After calling this method (or `start_server` or `connect`), you
            should no longer directly read from or write to the original socket
            object.

        :param .threading.Event event:
            an event to trigger when negotiation is complete (optional)

        :param float timeout:
            a timeout, in seconds, for SSH2 session negotiation (optional)

        :raises:
            `.SSHException` -- if negotiation fails (and no ``event`` was
            passed in)
        """
        self.active = True
        if event is not None:
            # async, return immediately and let the app poll for completion
            self.completion_event = event
            self.start()
            return

        # synchronous, wait for a result
        self.completion_event = event = threading.Event()
        self.start()
        max_time = time.time() + timeout if timeout is not None else None
        while True:
            event.wait(0.1)
            if not self.active:
                e = self.get_exception()
                if e is not None:
                    raise e
                raise SSHException("Negotiation failed.")
            if event.is_set() or (
                timeout is not None and time.time() >= max_time
            ):
                break

    def start_server(self, event=None, server=None):
        """
        Negotiate a new SSH2 session as a server.  This is the first step after
        creating a new `.Transport` and setting up your server host key(s).  A
        separate thread is created for protocol negotiation.

        If an event is passed in, this method returns immediately.  When
        negotiation is done (successful or not), the given ``Event`` will
        be triggered.  On failure, `is_active` will return ``False``.

        (Since 1.4) If ``event`` is ``None``, this method will not return until
        negotiation is done.  On success, the method returns normally.
        Otherwise an SSHException is raised.

        After a successful negotiation, the client will need to authenticate.
        Override the methods `get_allowed_auths
        <.ServerInterface.get_allowed_auths>`, `check_auth_none
        <.ServerInterface.check_auth_none>`, `check_auth_password
        <.ServerInterface.check_auth_password>`, and `check_auth_publickey
        <.ServerInterface.check_auth_publickey>` in the given ``server`` object
        to control the authentication process.

        After a successful authentication, the client should request to open a
        channel.  Override `check_channel_request
        <.ServerInterface.check_channel_request>` in the given ``server``
        object to allow channels to be opened.

        .. note::
            After calling this method (or `start_client` or `connect`), you
            should no longer directly read from or write to the original socket
            object.

        :param .threading.Event event:
            an event to trigger when negotiation is complete.
        :param .ServerInterface server:
            an object used to perform authentication and create `channels
            <.Channel>`

        :raises:
            `.SSHException` -- if negotiation fails (and no ``event`` was
            passed in)
        """
        if server is None:
            server = ServerInterface()
        self.server_mode = True
        self.server_object = server
        self.active = True
        if event is not None:
            # async, return immediately and let the app poll for completion
            self.completion_event = event
            self.start()
            return

        # synchronous, wait for a result
        self.completion_event = event = threading.Event()
        self.start()
        while True:
            event.wait(0.1)
            if not self.active:
                e = self.get_exception()
                if e is not None:
                    raise e
                raise SSHException("Negotiation failed.")
            if event.is_set():
                break

    def add_server_key(self, key):
        """
        Add a host key to the list of keys used for server mode.  When behaving
        as a server, the host key is used to sign certain packets during the
        SSH2 negotiation, so that the client can trust that we are who we say
        we are.  Because this is used for signing, the key must contain private
        key info, not just the public half.  Only one key of each type is kept.

        :param .PKey key:
            the host key (instance of some subclass) to add
        """
        self.server_key_dict[key.get_name()] = key
        # Handle SHA-2 extensions for RSA by ensuring that lookups into
        # self.server_key_dict will yield this key for any of the algorithm
        # names.
        if isinstance(key, RSAKey):
            self.server_key_dict["rsa-sha2-256"] = key
            self.server_key_dict["rsa-sha2-512"] = key

    def get_server_key(self):
        """
        Return the active host key, in server mode.  After negotiating with the
        client, this method will return the negotiated host key.  If only one
        type of host key was set with `add_server_key`, that's the only key
        that will ever be returned.  But in cases where you have set more than
        one type of host key, the key type will be negotiated by the client,
        and this method will return the key of the type agreed on.  If the host
        key has not been negotiated yet, ``None`` is returned.  In client mode,
        the behavior is undefined.

        :return:
            host key (`.PKey`) of the type negotiated by the client, or
            ``None``.
        """
        try:
            return self.server_key_dict[self.host_key_type]
        except KeyError:
            pass
        return None

    @staticmethod
    def load_server_moduli(filename=None):
        """
        (optional)
        Load a file of prime moduli for use in doing group-exchange key
        negotiation in server mode.  It's a rather obscure option and can be
        safely ignored.

        In server mode, the remote client may request "group-exchange" key
        negotiation, which asks the server to send a random prime number that
        fits certain criteria.  These primes are pretty difficult to compute,
        so they can't be generated on demand.  But many systems contain a file
        of suitable primes (usually named something like ``/etc/ssh/moduli``).
        If you call `load_server_moduli` and it returns ``True``, then this
        file of primes has been loaded and we will support "group-exchange" in
        server mode.  Otherwise server mode will just claim that it doesn't
        support that method of key negotiation.

        :param str filename:
            optional path to the moduli file, if you happen to know that it's
            not in a standard location.
        :return:
            True if a moduli file was successfully loaded; False otherwise.

        .. note:: This has no effect when used in client mode.
        """
        Transport._modulus_pack = ModulusPack()
        # places to look for the openssh "moduli" file
        file_list = ["/etc/ssh/moduli", "/usr/local/etc/moduli"]
        if filename is not None:
            file_list.insert(0, filename)
        for fn in file_list:
            try:
                Transport._modulus_pack.read_file(fn)
                return True
            except IOError:
                pass
        # none succeeded
        Transport._modulus_pack = None
        return False

    def close(self):
        """
        Close this session, and any open channels that are tied to it.
        """
        if not self.active:
            return
        self.stop_thread()
        for chan in list(self._channels.values()):
            chan._unlink()
        self.sock.close()

    def get_remote_server_key(self):
        """
        Return the host key of the server (in client mode).

        .. note::
            Previously this call returned a tuple of ``(key type, key
            string)``. You can get the same effect by calling `.PKey.get_name`
            for the key type, and ``str(key)`` for the key string.

        :raises: `.SSHException` -- if no session is currently active.

        :return: public key (`.PKey`) of the remote server
        """
        if (not self.active) or (not self.initial_kex_done):
            raise SSHException("No existing session")
        return self.host_key

    def is_active(self):
        """
        Return true if this session is active (open).

        :return:
            True if the session is still active (open); False if the session is
            closed
        """
        return self.active

    def open_session(
        self, window_size=None, max_packet_size=None, timeout=None
    ):
        """
        Request a new channel to the server, of type ``"session"``.  This is
        just an alias for calling `open_channel` with an argument of
        ``"session"``.

        .. note:: Modifying the the window and packet sizes might have adverse
            effects on the session created. The default values are the same
            as in the OpenSSH code base and have been battle tested.

        :param int window_size:
            optional window size for this session.
        :param int max_packet_size:
            optional max packet size for this session.

        :return: a new `.Channel`

        :raises:
            `.SSHException` -- if the request is rejected or the session ends
            prematurely

        .. versionchanged:: 1.13.4/1.14.3/1.15.3
            Added the ``timeout`` argument.
        .. versionchanged:: 1.15
            Added the ``window_size`` and ``max_packet_size`` arguments.
        """
        return self.open_channel(
            "session",
            window_size=window_size,
            max_packet_size=max_packet_size,
            timeout=timeout,
        )

    def open_x11_channel(self, src_addr=None):
        """
        Request a new channel to the client, of type ``"x11"``.  This
        is just an alias for ``open_channel('x11', src_addr=src_addr)``.

        :param tuple src_addr:
            the source address (``(str, int)``) of the x11 server (port is the
            x11 port, ie. 6010)
        :return: a new `.Channel`

        :raises:
            `.SSHException` -- if the request is rejected or the session ends
            prematurely
        """
        return self.open_channel("x11", src_addr=src_addr)

    def open_forward_agent_channel(self):
        """
        Request a new channel to the client, of type
        ``"auth-agent@openssh.com"``.

        This is just an alias for ``open_channel('auth-agent@openssh.com')``.

        :return: a new `.Channel`

        :raises: `.SSHException` --
            if the request is rejected or the session ends prematurely
        """
        return self.open_channel("auth-agent@openssh.com")

    def open_forwarded_tcpip_channel(self, src_addr, dest_addr):
        """
        Request a new channel back to the client, of type ``forwarded-tcpip``.

        This is used after a client has requested port forwarding, for sending
        incoming connections back to the client.

        :param src_addr: originator's address
        :param dest_addr: local (server) connected address
        """
        return self.open_channel("forwarded-tcpip", dest_addr, src_addr)

    def open_channel(
        self,
        kind,
        dest_addr=None,
        src_addr=None,
        window_size=None,
        max_packet_size=None,
        timeout=None,
    ):
        """
        Request a new channel to the server. `Channels <.Channel>` are
        socket-like objects used for the actual transfer of data across the
        session. You may only request a channel after negotiating encryption
        (using `connect` or `start_client`) and authenticating.

        .. note:: Modifying the the window and packet sizes might have adverse
            effects on the channel created. The default values are the same
            as in the OpenSSH code base and have been battle tested.

        :param str kind:
            the kind of channel requested (usually ``"session"``,
            ``"forwarded-tcpip"``, ``"direct-tcpip"``, or ``"x11"``)
        :param tuple dest_addr:
            the destination address (address + port tuple) of this port
            forwarding, if ``kind`` is ``"forwarded-tcpip"`` or
            ``"direct-tcpip"`` (ignored for other channel types)
        :param src_addr: the source address of this port forwarding, if
            ``kind`` is ``"forwarded-tcpip"``, ``"direct-tcpip"``, or ``"x11"``
        :param int window_size:
            optional window size for this session.
        :param int max_packet_size:
            optional max packet size for this session.
        :param float timeout:
            optional timeout opening a channel, default 3600s (1h)

        :return: a new `.Channel` on success

        :raises:
            `.SSHException` -- if the request is rejected, the session ends
            prematurely or there is a timeout opening a channel

        .. versionchanged:: 1.15
            Added the ``window_size`` and ``max_packet_size`` arguments.
        """
        if not self.active:
            raise SSHException("SSH session not active")
        timeout = self.channel_timeout if timeout is None else timeout
        self.lock.acquire()
        try:
            window_size = self._sanitize_window_size(window_size)
            max_packet_size = self._sanitize_packet_size(max_packet_size)
            chanid = self._next_channel()
            m = Message()
            m.add_byte(cMSG_CHANNEL_OPEN)
            m.add_string(kind)
            m.add_int(chanid)
            m.add_int(window_size)
            m.add_int(max_packet_size)
            if (kind == "forwarded-tcpip") or (kind == "direct-tcpip"):
                m.add_string(dest_addr[0])
                m.add_int(dest_addr[1])
                m.add_string(src_addr[0])
                m.add_int(src_addr[1])
            elif kind == "x11":
                m.add_string(src_addr[0])
                m.add_int(src_addr[1])
            chan = Channel(chanid)
            self._channels.put(chanid, chan)
            self.channel_events[chanid] = event = threading.Event()
            self.channels_seen[chanid] = True
            chan._set_transport(self)
            chan._set_window(window_size, max_packet_size)
        finally:
            self.lock.release()
        self._send_user_message(m)
        start_ts = time.time()
        while True:
            event.wait(0.1)
            if not self.active:
                e = self.get_exception()
                if e is None:
                    e = SSHException("Unable to open channel.")
                raise e
            if event.is_set():
                break
            elif start_ts + timeout < time.time():
                raise SSHException("Timeout opening channel.")
        chan = self._channels.get(chanid)
        if chan is not None:
            return chan
        e = self.get_exception()
        if e is None:
            e = SSHException("Unable to open channel.")
        raise e

    def request_port_forward(self, address, port, handler=None):
        """
        Ask the server to forward TCP connections from a listening port on
        the server, across this SSH session.

        If a handler is given, that handler is called from a different thread
        whenever a forwarded connection arrives.  The handler parameters are::

            handler(
                channel,
                (origin_addr, origin_port),
                (server_addr, server_port),
            )

        where ``server_addr`` and ``server_port`` are the address and port that
        the server was listening on.

        If no handler is set, the default behavior is to send new incoming
        forwarded connections into the accept queue, to be picked up via
        `accept`.

        :param str address: the address to bind when forwarding
        :param int port:
            the port to forward, or 0 to ask the server to allocate any port
        :param callable handler:
            optional handler for incoming forwarded connections, of the form
            ``func(Channel, (str, int), (str, int))``.

        :return: the port number (`int`) allocated by the server

        :raises:
            `.SSHException` -- if the server refused the TCP forward request
        """
        if not self.active:
            raise SSHException("SSH session not active")
        port = int(port)
        response = self.global_request(
            "tcpip-forward", (address, port), wait=True
        )
        if response is None:
            raise SSHException("TCP forwarding request denied")
        if port == 0:
            port = response.get_int()
        if handler is None:

            def default_handler(channel, src_addr, dest_addr_port):
                # src_addr, src_port = src_addr_port
                # dest_addr, dest_port = dest_addr_port
                self._queue_incoming_channel(channel)

            handler = default_handler
        self._tcp_handler = handler
        return port

    def cancel_port_forward(self, address, port):
        """
        Ask the server to cancel a previous port-forwarding request.  No more
        connections to the given address & port will be forwarded across this
        ssh connection.

        :param str address: the address to stop forwarding
        :param int port: the port to stop forwarding
        """
        if not self.active:
            return
        self._tcp_handler = None
        self.global_request("cancel-tcpip-forward", (address, port), wait=True)

    def open_sftp_client(self):
        """
        Create an SFTP client channel from an open transport.  On success, an
        SFTP session will be opened with the remote host, and a new
        `.SFTPClient` object will be returned.

        :return:
            a new `.SFTPClient` referring to an sftp session (channel) across
            this transport
        """
        return SFTPClient.from_transport(self)

    def send_ignore(self, byte_count=None):
        """
        Send a junk packet across the encrypted link.  This is sometimes used
        to add "noise" to a connection to confuse would-be attackers.  It can
        also be used as a keep-alive for long lived connections traversing
        firewalls.

        :param int byte_count:
            the number of random bytes to send in the payload of the ignored
            packet -- defaults to a random number from 10 to 41.
        """
        m = Message()
        m.add_byte(cMSG_IGNORE)
        if byte_count is None:
            byte_count = (byte_ord(os.urandom(1)) % 32) + 10
        m.add_bytes(os.urandom(byte_count))
        self._send_user_message(m)

    def renegotiate_keys(self):
        """
        Force this session to switch to new keys.  Normally this is done
        automatically after the session hits a certain number of packets or
        bytes sent or received, but this method gives you the option of forcing
        new keys whenever you want.  Negotiating new keys causes a pause in
        traffic both ways as the two sides swap keys and do computations.  This
        method returns when the session has switched to new keys.

        :raises:
            `.SSHException` -- if the key renegotiation failed (which causes
            the session to end)
        """
        self.completion_event = threading.Event()
        self._send_kex_init()
        while True:
            self.completion_event.wait(0.1)
            if not self.active:
                e = self.get_exception()
                if e is not None:
                    raise e
                raise SSHException("Negotiation failed.")
            if self.completion_event.is_set():
                break
        return

    def set_keepalive(self, interval):
        """
        Turn on/off keepalive packets (default is off).  If this is set, after
        ``interval`` seconds without sending any data over the connection, a
        "keepalive" packet will be sent (and ignored by the remote host).  This
        can be useful to keep connections alive over a NAT, for example.

        :param int interval:
            seconds to wait before sending a keepalive packet (or
            0 to disable keepalives).
        """

        def _request(x=weakref.proxy(self)):
            return x.global_request("keepalive@lag.net", wait=False)

        self.packetizer.set_keepalive(interval, _request)

    def global_request(self, kind, data=None, wait=True):
        """
        Make a global request to the remote host.  These are normally
        extensions to the SSH2 protocol.

        :param str kind: name of the request.
        :param tuple data:
            an optional tuple containing additional data to attach to the
            request.
        :param bool wait:
            ``True`` if this method should not return until a response is
            received; ``False`` otherwise.
        :return:
            a `.Message` containing possible additional data if the request was
            successful (or an empty `.Message` if ``wait`` was ``False``);
            ``None`` if the request was denied.
        """
        if wait:
            self.completion_event = threading.Event()
        m = Message()
        m.add_byte(cMSG_GLOBAL_REQUEST)
        m.add_string(kind)
        m.add_boolean(wait)
        if data is not None:
            m.add(*data)
        self._log(DEBUG, 'Sending global request "{}"'.format(kind))
        self._send_user_message(m)
        if not wait:
            return None
        while True:
            self.completion_event.wait(0.1)
            if not self.active:
                return None
            if self.completion_event.is_set():
                break
        return self.global_response

    def accept(self, timeout=None):
        """
        Return the next channel opened by the client over this transport, in
        server mode.  If no channel is opened before the given timeout,
        ``None`` is returned.

        :param int timeout:
            seconds to wait for a channel, or ``None`` to wait forever
        :return: a new `.Channel` opened by the client
        """
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

    def connect(
        self,
        hostkey=None,
        username="",
        password=None,
        pkey=None,
        gss_host=None,
        gss_auth=False,
        gss_kex=False,
        gss_deleg_creds=True,
        gss_trust_dns=True,
    ):
        """
        Negotiate an SSH2 session, and optionally verify the server's host key
        and authenticate using a password or private key.  This is a shortcut
        for `start_client`, `get_remote_server_key`, and
        `Transport.auth_password` or `Transport.auth_publickey`.  Use those
        methods if you want more control.

        You can use this method immediately after creating a Transport to
        negotiate encryption with a server.  If it fails, an exception will be
        thrown.  On success, the method will return cleanly, and an encrypted
        session exists.  You may immediately call `open_channel` or
        `open_session` to get a `.Channel` object, which is used for data
        transfer.

        .. note::
            If you fail to supply a password or private key, this method may
            succeed, but a subsequent `open_channel` or `open_session` call may
            fail because you haven't authenticated yet.

        :param .PKey hostkey:
            the host key expected from the server, or ``None`` if you don't
            want to do host key verification.
        :param str username: the username to authenticate as.
        :param str password:
            a password to use for authentication, if you want to use password
            authentication; otherwise ``None``.
        :param .PKey pkey:
            a private key to use for authentication, if you want to use private
            key authentication; otherwise ``None``.
        :param str gss_host:
            The target's name in the kerberos database. Default: hostname
        :param bool gss_auth:
            ``True`` if you want to use GSS-API authentication.
        :param bool gss_kex:
            Perform GSS-API Key Exchange and user authentication.
        :param bool gss_deleg_creds:
            Whether to delegate GSS-API client credentials.
        :param gss_trust_dns:
            Indicates whether or not the DNS is trusted to securely
            canonicalize the name of the host being connected to (default
            ``True``).

        :raises: `.SSHException` -- if the SSH2 negotiation fails, the host key
            supplied by the server is incorrect, or authentication fails.

        .. versionchanged:: 2.3
            Added the ``gss_trust_dns`` argument.
        """
        if hostkey is not None:
            # TODO: a more robust implementation would be to ask each key class
            # for its nameS plural, and just use that.
            # TODO: that could be used in a bunch of other spots too
            if isinstance(hostkey, RSAKey):
                self._preferred_keys = [
                    "rsa-sha2-512",
                    "rsa-sha2-256",
                    "ssh-rsa",
                ]
            else:
                self._preferred_keys = [hostkey.get_name()]

        self.set_gss_host(
            gss_host=gss_host,
            trust_dns=gss_trust_dns,
            gssapi_requested=gss_kex or gss_auth,
        )

        self.start_client()

        # check host key if we were given one
        # If GSS-API Key Exchange was performed, we are not required to check
        # the host key.
        if (hostkey is not None) and not gss_kex:
            key = self.get_remote_server_key()
            if (
                key.get_name() != hostkey.get_name()
                or key.asbytes() != hostkey.asbytes()
            ):
                self._log(DEBUG, "Bad host key from server")
                self._log(
                    DEBUG,
                    "Expected: {}: {}".format(
                        hostkey.get_name(), repr(hostkey.asbytes())
                    ),
                )
                self._log(
                    DEBUG,
                    "Got     : {}: {}".format(
                        key.get_name(), repr(key.asbytes())
                    ),
                )
                raise SSHException("Bad host key from server")
            self._log(
                DEBUG, "Host key verified ({})".format(hostkey.get_name())
            )

        if (pkey is not None) or (password is not None) or gss_auth or gss_kex:
            if gss_auth:
                self._log(
                    DEBUG, "Attempting GSS-API auth... (gssapi-with-mic)"
                )  # noqa
                self.auth_gssapi_with_mic(
                    username, self.gss_host, gss_deleg_creds
                )
            elif gss_kex:
                self._log(DEBUG, "Attempting GSS-API auth... (gssapi-keyex)")
                self.auth_gssapi_keyex(username)
            elif pkey is not None:
                self._log(DEBUG, "Attempting public-key auth...")
                self.auth_publickey(username, pkey)
            else:
                self._log(DEBUG, "Attempting password auth...")
                self.auth_password(username, password)

        return

    def get_exception(self):
        """
        Return any exception that happened during the last server request.
        This can be used to fetch more specific error information after using
        calls like `start_client`.  The exception (if any) is cleared after
        this call.

        :return:
            an exception, or ``None`` if there is no stored exception.

        .. versionadded:: 1.1
        """
        self.lock.acquire()
        try:
            e = self.saved_exception
            self.saved_exception = None
            return e
        finally:
            self.lock.release()

    def set_subsystem_handler(self, name, handler, *args, **kwargs):
        """
        Set the handler class for a subsystem in server mode.  If a request
        for this subsystem is made on an open ssh channel later, this handler
        will be constructed and called -- see `.SubsystemHandler` for more
        detailed documentation.

        Any extra parameters (including keyword arguments) are saved and
        passed to the `.SubsystemHandler` constructor later.

        :param str name: name of the subsystem.
        :param handler:
            subclass of `.SubsystemHandler` that handles this subsystem.
        """
        try:
            self.lock.acquire()
            self.subsystem_table[name] = (handler, args, kwargs)
        finally:
            self.lock.release()

    def is_authenticated(self):
        """
        Return true if this session is active and authenticated.

        :return:
            True if the session is still open and has been authenticated
            successfully; False if authentication failed and/or the session is
            closed.
        """
        return (
            self.active
            and self.auth_handler is not None
            and self.auth_handler.is_authenticated()
        )

    def get_username(self):
        """
        Return the username this connection is authenticated for.  If the
        session is not authenticated (or authentication failed), this method
        returns ``None``.

        :return: username that was authenticated (a `str`), or ``None``.
        """
        if not self.active or (self.auth_handler is None):
            return None
        return self.auth_handler.get_username()

    def get_banner(self):
        """
        Return the banner supplied by the server upon connect. If no banner is
        supplied, this method returns ``None``.

        :returns: server supplied banner (`str`), or ``None``.

        .. versionadded:: 1.13
        """
        if not self.active or (self.auth_handler is None):
            return None
        return self.auth_handler.banner

    def auth_none(self, username):
        """
        Try to authenticate to the server using no authentication at all.
        This will almost always fail.  It may be useful for determining the
        list of authentication types supported by the server, by catching the
        `.BadAuthenticationType` exception raised.

        :param str username: the username to authenticate as
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty)

        :raises:
            `.BadAuthenticationType` -- if "none" authentication isn't allowed
            by the server for this user
        :raises:
            `.SSHException` -- if the authentication failed due to a network
            error

        .. versionadded:: 1.5
        """
        if (not self.active) or (not self.initial_kex_done):
            raise SSHException("No existing session")
        my_event = threading.Event()
        self.auth_handler = AuthHandler(self)
        self.auth_handler.auth_none(username, my_event)
        return self.auth_handler.wait_for_response(my_event)

    def auth_password(self, username, password, event=None, fallback=True):
        """
        Authenticate to the server using a password.  The username and password
        are sent over an encrypted link.

        If an ``event`` is passed in, this method will return immediately, and
        the event will be triggered once authentication succeeds or fails.  On
        success, `is_authenticated` will return ``True``.  On failure, you may
        use `get_exception` to get more detailed error information.

        Since 1.1, if no event is passed, this method will block until the
        authentication succeeds or fails.  On failure, an exception is raised.
        Otherwise, the method simply returns.

        Since 1.5, if no event is passed and ``fallback`` is ``True`` (the
        default), if the server doesn't support plain password authentication
        but does support so-called "keyboard-interactive" mode, an attempt
        will be made to authenticate using this interactive mode.  If it fails,
        the normal exception will be thrown as if the attempt had never been
        made.  This is useful for some recent Gentoo and Debian distributions,
        which turn off plain password authentication in a misguided belief
        that interactive authentication is "more secure".  (It's not.)

        If the server requires multi-step authentication (which is very rare),
        this method will return a list of auth types permissible for the next
        step.  Otherwise, in the normal case, an empty list is returned.

        :param str username: the username to authenticate as
        :param basestring password: the password to authenticate with
        :param .threading.Event event:
            an event to trigger when the authentication attempt is complete
            (whether it was successful or not)
        :param bool fallback:
            ``True`` if an attempt at an automated "interactive" password auth
            should be made if the server doesn't support normal password auth
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty)

        :raises:
            `.BadAuthenticationType` -- if password authentication isn't
            allowed by the server for this user (and no event was passed in)
        :raises:
            `.AuthenticationException` -- if the authentication failed (and no
            event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to send the password unless we're on a secure
            # link
            raise SSHException("No existing session")
        if event is None:
            my_event = threading.Event()
        else:
            my_event = event
        self.auth_handler = AuthHandler(self)
        self.auth_handler.auth_password(username, password, my_event)
        if event is not None:
            # caller wants to wait for event themselves
            return []
        try:
            return self.auth_handler.wait_for_response(my_event)
        except BadAuthenticationType as e:
            # if password auth isn't allowed, but keyboard-interactive *is*,
            # try to fudge it
            if not fallback or ("keyboard-interactive" not in e.allowed_types):
                raise
            try:

                def handler(title, instructions, fields):
                    if len(fields) > 1:
                        raise SSHException("Fallback authentication failed.")
                    if len(fields) == 0:
                        # for some reason, at least on os x, a 2nd request will
                        # be made with zero fields requested.  maybe it's just
                        # to try to fake out automated scripting of the exact
                        # type we're doing here.  *shrug* :)
                        return []
                    return [password]

                return self.auth_interactive(username, handler)
            except SSHException:
                # attempt failed; just raise the original exception
                raise e

    def auth_publickey(self, username, key, event=None):
        """
        Authenticate to the server using a private key.  The key is used to
        sign data from the server, so it must include the private part.

        If an ``event`` is passed in, this method will return immediately, and
        the event will be triggered once authentication succeeds or fails.  On
        success, `is_authenticated` will return ``True``.  On failure, you may
        use `get_exception` to get more detailed error information.

        Since 1.1, if no event is passed, this method will block until the
        authentication succeeds or fails.  On failure, an exception is raised.
        Otherwise, the method simply returns.

        If the server requires multi-step authentication (which is very rare),
        this method will return a list of auth types permissible for the next
        step.  Otherwise, in the normal case, an empty list is returned.

        :param str username: the username to authenticate as
        :param .PKey key: the private key to authenticate with
        :param .threading.Event event:
            an event to trigger when the authentication attempt is complete
            (whether it was successful or not)
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty)

        :raises:
            `.BadAuthenticationType` -- if public-key authentication isn't
            allowed by the server for this user (and no event was passed in)
        :raises:
            `.AuthenticationException` -- if the authentication failed (and no
            event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException("No existing session")
        if event is None:
            my_event = threading.Event()
        else:
            my_event = event
        self.auth_handler = AuthHandler(self)
        self.auth_handler.auth_publickey(username, key, my_event)
        if event is not None:
            # caller wants to wait for event themselves
            return []
        return self.auth_handler.wait_for_response(my_event)

    def auth_interactive(self, username, handler, submethods=""):
        """
        Authenticate to the server interactively.  A handler is used to answer
        arbitrary questions from the server.  On many servers, this is just a
        dumb wrapper around PAM.

        This method will block until the authentication succeeds or fails,
        periodically calling the handler asynchronously to get answers to
        authentication questions.  The handler may be called more than once
        if the server continues to ask questions.

        The handler is expected to be a callable that will handle calls of the
        form: ``handler(title, instructions, prompt_list)``.  The ``title`` is
        meant to be a dialog-window title, and the ``instructions`` are user
        instructions (both are strings).  ``prompt_list`` will be a list of
        prompts, each prompt being a tuple of ``(str, bool)``.  The string is
        the prompt and the boolean indicates whether the user text should be
        echoed.

        A sample call would thus be:
        ``handler('title', 'instructions', [('Password:', False)])``.

        The handler should return a list or tuple of answers to the server's
        questions.

        If the server requires multi-step authentication (which is very rare),
        this method will return a list of auth types permissible for the next
        step.  Otherwise, in the normal case, an empty list is returned.

        :param str username: the username to authenticate as
        :param callable handler: a handler for responding to server questions
        :param str submethods: a string list of desired submethods (optional)
        :return:
            list of auth types permissible for the next stage of
            authentication (normally empty).

        :raises: `.BadAuthenticationType` -- if public-key authentication isn't
            allowed by the server for this user
        :raises: `.AuthenticationException` -- if the authentication failed
        :raises: `.SSHException` -- if there was a network error

        .. versionadded:: 1.5
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException("No existing session")
        my_event = threading.Event()
        self.auth_handler = AuthHandler(self)
        self.auth_handler.auth_interactive(
            username, handler, my_event, submethods
        )
        return self.auth_handler.wait_for_response(my_event)

    def auth_interactive_dumb(self, username, handler=None, submethods=""):
        """
        Authenticate to the server interactively but dumber.
        Just print the prompt and / or instructions to stdout and send back
        the response. This is good for situations where partial auth is
        achieved by key and then the user has to enter a 2fac token.
        """

        if not handler:

            def handler(title, instructions, prompt_list):
                answers = []
                if title:
                    print(title.strip())
                if instructions:
                    print(instructions.strip())
                for prompt, show_input in prompt_list:
                    print(prompt.strip(), end=" ")
                    answers.append(input())
                return answers

        return self.auth_interactive(username, handler, submethods)

    def auth_gssapi_with_mic(self, username, gss_host, gss_deleg_creds):
        """
        Authenticate to the Server using GSS-API / SSPI.

        :param str username: The username to authenticate as
        :param str gss_host: The target host
        :param bool gss_deleg_creds: Delegate credentials or not
        :return: list of auth types permissible for the next stage of
                 authentication (normally empty)
        :raises: `.BadAuthenticationType` -- if gssapi-with-mic isn't
            allowed by the server (and no event was passed in)
        :raises:
            `.AuthenticationException` -- if the authentication failed (and no
            event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException("No existing session")
        my_event = threading.Event()
        self.auth_handler = AuthHandler(self)
        self.auth_handler.auth_gssapi_with_mic(
            username, gss_host, gss_deleg_creds, my_event
        )
        return self.auth_handler.wait_for_response(my_event)

    def auth_gssapi_keyex(self, username):
        """
        Authenticate to the server with GSS-API/SSPI if GSS-API kex is in use.

        :param str username: The username to authenticate as.
        :returns:
            a list of auth types permissible for the next stage of
            authentication (normally empty)
        :raises: `.BadAuthenticationType` --
            if GSS-API Key Exchange was not performed (and no event was passed
            in)
        :raises: `.AuthenticationException` --
            if the authentication failed (and no event was passed in)
        :raises: `.SSHException` -- if there was a network error
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException("No existing session")
        my_event = threading.Event()
        self.auth_handler = AuthHandler(self)
        self.auth_handler.auth_gssapi_keyex(username, my_event)
        return self.auth_handler.wait_for_response(my_event)

    def set_log_channel(self, name):
        """
        Set the channel for this transport's logging.  The default is
        ``"paramiko.transport"`` but it can be set to anything you want. (See
        the `.logging` module for more info.)  SSH Channels will log to a
        sub-channel of the one specified.

        :param str name: new channel name for logging

        .. versionadded:: 1.1
        """
        self.log_name = name
        self.logger = util.get_logger(name)
        self.packetizer.set_log(self.logger)

    def get_log_channel(self):
        """
        Return the channel name used for this transport's logging.

        :return: channel name as a `str`

        .. versionadded:: 1.2
        """
        return self.log_name

    def set_hexdump(self, hexdump):
        """
        Turn on/off logging a hex dump of protocol traffic at DEBUG level in
        the logs.  Normally you would want this off (which is the default),
        but if you are debugging something, it may be useful.

        :param bool hexdump:
            ``True`` to log protocol traffix (in hex) to the log; ``False``
            otherwise.
        """
        self.packetizer.set_hexdump(hexdump)

    def get_hexdump(self):
        """
        Return ``True`` if the transport is currently logging hex dumps of
        protocol traffic.

        :return: ``True`` if hex dumps are being logged, else ``False``.

        .. versionadded:: 1.4
        """
        return self.packetizer.get_hexdump()

    def use_compression(self, compress=True):
        """
        Turn on/off compression.  This will only have an affect before starting
        the transport (ie before calling `connect`, etc).  By default,
        compression is off since it negatively affects interactive sessions.

        :param bool compress:
            ``True`` to ask the remote client/server to compress traffic;
            ``False`` to refuse compression

        .. versionadded:: 1.5.2
        """
        if compress:
            self._preferred_compression = ("zlib@openssh.com", "zlib", "none")
        else:
            self._preferred_compression = ("none",)

    def getpeername(self):
        """
        Return the address of the remote side of this Transport, if possible.

        This is effectively a wrapper around ``getpeername`` on the underlying
        socket.  If the socket-like object has no ``getpeername`` method, then
        ``("unknown", 0)`` is returned.

        :return:
            the address of the remote host, if known, as a ``(str, int)``
            tuple.
        """
        gp = getattr(self.sock, "getpeername", None)
        if gp is None:
            return "unknown", 0
        return gp()

    def stop_thread(self):
        self.active = False
        self.packetizer.close()
        # Keep trying to join() our main thread, quickly, until:
        # * We join()ed successfully (self.is_alive() == False)
        # * Or it looks like we've hit issue #520 (socket.recv hitting some
        # race condition preventing it from timing out correctly), wherein
        # our socket and packetizer are both closed (but where we'd
        # otherwise be sitting forever on that recv()).
        while (
            self.is_alive()
            and self is not threading.current_thread()
            and not self.sock._closed
            and not self.packetizer.closed
        ):
            self.join(0.1)

    # internals...

    # TODO 4.0: make a public alias for this because multiple other classes
    # already explicitly rely on it...or just rewrite logging :D
    def _log(self, level, msg, *args):
        if issubclass(type(msg), list):
            for m in msg:
                self.logger.log(level, m)
        else:
            self.logger.log(level, msg, *args)

    def _get_modulus_pack(self):
        """used by KexGex to find primes for group exchange"""
        return self._modulus_pack

    def _next_channel(self):
        """you are holding the lock"""
        chanid = self._channel_counter
        while self._channels.get(chanid) is not None:
            self._channel_counter = (self._channel_counter + 1) & 0xFFFFFF
            chanid = self._channel_counter
        self._channel_counter = (self._channel_counter + 1) & 0xFFFFFF
        return chanid

    def _unlink_channel(self, chanid):
        """used by a Channel to remove itself from the active channel list"""
        self._channels.delete(chanid)

    def _send_message(self, data):
        self.packetizer.send_message(data)

    def _send_user_message(self, data):
        """
        send a message, but block if we're in key negotiation.  this is used
        for user-initiated requests.
        """
        start = time.time()
        while True:
            self.clear_to_send.wait(0.1)
            if not self.active:
                self._log(
                    DEBUG, "Dropping user packet because connection is dead."
                )  # noqa
                return
            self.clear_to_send_lock.acquire()
            if self.clear_to_send.is_set():
                break
            self.clear_to_send_lock.release()
            if time.time() > start + self.clear_to_send_timeout:
                raise SSHException(
                    "Key-exchange timed out waiting for key negotiation"
                )  # noqa
        try:
            self._send_message(data)
        finally:
            self.clear_to_send_lock.release()

    def _set_K_H(self, k, h):
        """
        Used by a kex obj to set the K (root key) and H (exchange hash).
        """
        self.K = k
        self.H = h
        if self.session_id is None:
            self.session_id = h

    def _expect_packet(self, *ptypes):
        """
        Used by a kex obj to register the next packet type it expects to see.
        """
        self._expected_packet = tuple(ptypes)

    def _verify_key(self, host_key, sig):
        key = self._key_info[self.host_key_type](Message(host_key))
        if key is None:
            raise SSHException("Unknown host key type")
        if not key.verify_ssh_sig(self.H, Message(sig)):
            raise SSHException(
                "Signature verification ({}) failed.".format(
                    self.host_key_type
                )
            )  # noqa
        self.host_key = key

    def _compute_key(self, id, nbytes):
        """id is 'A' - 'F' for the various keys used by ssh"""
        m = Message()
        m.add_mpint(self.K)
        m.add_bytes(self.H)
        m.add_byte(b(id))
        m.add_bytes(self.session_id)
        # Fallback to SHA1 for kex engines that fail to specify a hex
        # algorithm, or for e.g. transport tests that don't run kexinit.
        hash_algo = getattr(self.kex_engine, "hash_algo", None)
        hash_select_msg = "kex engine {} specified hash_algo {!r}".format(
            self.kex_engine.__class__.__name__, hash_algo
        )
        if hash_algo is None:
            hash_algo = sha1
            hash_select_msg += ", falling back to sha1"
        if not hasattr(self, "_logged_hash_selection"):
            self._log(DEBUG, hash_select_msg)
            setattr(self, "_logged_hash_selection", True)
        out = sofar = hash_algo(m.asbytes()).digest()
        while len(out) < nbytes:
            m = Message()
            m.add_mpint(self.K)
            m.add_bytes(self.H)
            m.add_bytes(sofar)
            digest = hash_algo(m.asbytes()).digest()
            out += digest
            sofar += digest
        return out[:nbytes]

    def _get_engine(self, name, key, iv=None, operation=None, aead=False):
        if name not in self._cipher_info:
            raise SSHException("Unknown cipher " + name)
        info = self._cipher_info[name]
        algorithm = info["class"](key)
        # AEAD types (eg GCM) use their algorithm class /as/ the encryption
        # engine (they expose the same encrypt/decrypt API as a CipherContext)
        if aead:
            return algorithm
        # All others go through the Cipher class.
        cipher = Cipher(
            algorithm=algorithm,
            # TODO: why is this getting tickled in aesgcm mode???
            mode=info["mode"](iv),
            backend=default_backend(),
        )
        if operation is self._ENCRYPT:
            return cipher.encryptor()
        else:
            return cipher.decryptor()

    def _set_forward_agent_handler(self, handler):
        if handler is None:

            def default_handler(channel):
                self._queue_incoming_channel(channel)

            self._forward_agent_handler = default_handler
        else:
            self._forward_agent_handler = handler

    def _set_x11_handler(self, handler):
        # only called if a channel has turned on x11 forwarding
        if handler is None:
            # by default, use the same mechanism as accept()
            def default_handler(channel, src_addr_port):
                self._queue_incoming_channel(channel)

            self._x11_handler = default_handler
        else:
            self._x11_handler = handler

    def _queue_incoming_channel(self, channel):
        self.lock.acquire()
        try:
            self.server_accepts.append(channel)
            self.server_accept_cv.notify()
        finally:
            self.lock.release()

    def _sanitize_window_size(self, window_size):
        if window_size is None:
            window_size = self.default_window_size
        return clamp_value(MIN_WINDOW_SIZE, window_size, MAX_WINDOW_SIZE)

    def _sanitize_packet_size(self, max_packet_size):
        if max_packet_size is None:
            max_packet_size = self.default_max_packet_size
        return clamp_value(MIN_PACKET_SIZE, max_packet_size, MAX_WINDOW_SIZE)

    def _ensure_authed(self, ptype, message):
        """
        Checks message type against current auth state.

        If server mode, and auth has not succeeded, and the message is of a
        post-auth type (channel open or global request) an appropriate error
        response Message is crafted and returned to caller for sending.

        Otherwise (client mode, authed, or pre-auth message) returns None.
        """
        if (
            not self.server_mode
            or ptype <= HIGHEST_USERAUTH_MESSAGE_ID
            or self.is_authenticated()
        ):
            return None
        # WELP. We must be dealing with someone trying to do non-auth things
        # without being authed. Tell them off, based on message class.
        reply = Message()
        # Global requests have no details, just failure.
        if ptype == MSG_GLOBAL_REQUEST:
            reply.add_byte(cMSG_REQUEST_FAILURE)
        # Channel opens let us reject w/ a specific type + message.
        elif ptype == MSG_CHANNEL_OPEN:
            kind = message.get_text()  # noqa
            chanid = message.get_int()
            reply.add_byte(cMSG_CHANNEL_OPEN_FAILURE)
            reply.add_int(chanid)
            reply.add_int(OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)
            reply.add_string("")
            reply.add_string("en")
        # NOTE: Post-open channel messages do not need checking; the above will
        # reject attempts to open channels, meaning that even if a malicious
        # user tries to send a MSG_CHANNEL_REQUEST, it will simply fall under
        # the logic that handles unknown channel IDs (as the channel list will
        # be empty.)
        return reply

    def _enforce_strict_kex(self, ptype):
        """
        Conditionally raise `MessageOrderError` during strict initial kex.

        This method should only be called inside code that handles non-KEXINIT
        messages; it does not interrogate ``ptype`` besides using it to log
        more accurately.
        """
        if self.agreed_on_strict_kex and not self.initial_kex_done:
            name = MSG_NAMES.get(ptype, f"msg {ptype}")
            raise MessageOrderError(
                f"In strict-kex mode, but was sent {name!r}!"
            )

    def run(self):
        # (use the exposed "run" method, because if we specify a thread target
        # of a private method, threading.Thread will keep a reference to it
        # indefinitely, creating a GC cycle and not letting Transport ever be
        # GC'd. it's a bug in Thread.)

        # Hold reference to 'sys' so we can test sys.modules to detect
        # interpreter shutdown.
        self.sys = sys

        # active=True occurs before the thread is launched, to avoid a race
        _active_threads.append(self)
        tid = hex(id(self) & xffffffff)
        if self.server_mode:
            self._log(DEBUG, "starting thread (server mode): {}".format(tid))
        else:
            self._log(DEBUG, "starting thread (client mode): {}".format(tid))
        try:
            try:
                self.packetizer.write_all(b(self.local_version + "\r\n"))
                self._log(
                    DEBUG,
                    "Local version/idstring: {}".format(self.local_version),
                )  # noqa
                self._check_banner()
                # The above is actually very much part of the handshake, but
                # sometimes the banner can be read but the machine is not
                # responding, for example when the remote ssh daemon is loaded
                # in to memory but we can not read from the disk/spawn a new
                # shell.
                # Make sure we can specify a timeout for the initial handshake.
                # Reuse the banner timeout for now.
                self.packetizer.start_handshake(self.handshake_timeout)
                self._send_kex_init()
                self._expect_packet(MSG_KEXINIT)

                while self.active:
                    if self.packetizer.need_rekey() and not self.in_kex:
                        self._send_kex_init()
                    try:
                        ptype, m = self.packetizer.read_message()
                    except NeedRekeyException:
                        continue
                    if ptype == MSG_IGNORE:
                        self._enforce_strict_kex(ptype)
                        continue
                    elif ptype == MSG_DISCONNECT:
                        self._parse_disconnect(m)
                        break
                    elif ptype == MSG_DEBUG:
                        self._enforce_strict_kex(ptype)
                        self._parse_debug(m)
                        continue
                    if len(self._expected_packet) > 0:
                        if ptype not in self._expected_packet:
                            exc_class = SSHException
                            if self.agreed_on_strict_kex:
                                exc_class = MessageOrderError
                            raise exc_class(
                                "Expecting packet from {!r}, got {:d}".format(
                                    self._expected_packet, ptype
                                )
                            )  # noqa
                        self._expected_packet = tuple()
                        # These message IDs indicate key exchange & will differ
                        # depending on exact exchange algorithm
                        if (ptype >= 30) and (ptype <= 41):
                            self.kex_engine.parse_next(ptype, m)
                            continue

                    if ptype in self._handler_table:
                        error_msg = self._ensure_authed(ptype, m)
                        if error_msg:
                            self._send_message(error_msg)
                        else:
                            self._handler_table[ptype](m)
                    elif ptype in self._channel_handler_table:
                        chanid = m.get_int()
                        chan = self._channels.get(chanid)
                        if chan is not None:
                            self._channel_handler_table[ptype](chan, m)
                        elif chanid in self.channels_seen:
                            self._log(
                                DEBUG,
                                "Ignoring message for dead channel {:d}".format(  # noqa
                                    chanid
                                ),
                            )
                        else:
                            self._log(
                                ERROR,
                                "Channel request for unknown channel {:d}".format(  # noqa
                                    chanid
                                ),
                            )
                            break
                    elif (
                        self.auth_handler is not None
                        and ptype in self.auth_handler._handler_table
                    ):
                        handler = self.auth_handler._handler_table[ptype]
                        handler(m)
                        if len(self._expected_packet) > 0:
                            continue
                    else:
                        # Respond with "I don't implement this particular
                        # message type" message (unless the message type was
                        # itself literally MSG_UNIMPLEMENTED, in which case, we
                        # just shut up to avoid causing a useless loop).
                        name = MSG_NAMES[ptype]
                        warning = "Oops, unhandled type {} ({!r})".format(
                            ptype, name
                        )
                        self._log(WARNING, warning)
                        if ptype != MSG_UNIMPLEMENTED:
                            msg = Message()
                            msg.add_byte(cMSG_UNIMPLEMENTED)
                            msg.add_int(m.seqno)
                            self._send_message(msg)
                    self.packetizer.complete_handshake()
            except SSHException as e:
                self._log(
                    ERROR,
                    "Exception ({}): {}".format(
                        "server" if self.server_mode else "client", e
                    ),
                )
                self._log(ERROR, util.tb_strings())
                self.saved_exception = e
            except EOFError as e:
                self._log(DEBUG, "EOF in transport thread")
                self.saved_exception = e
            except socket.error as e:
                if type(e.args) is tuple:
                    if e.args:
                        emsg = "{} ({:d})".format(e.args[1], e.args[0])
                    else:  # empty tuple, e.g. socket.timeout
                        emsg = str(e) or repr(e)
                else:
                    emsg = e.args
                self._log(ERROR, "Socket exception: " + emsg)
                self.saved_exception = e
            except Exception as e:
                self._log(ERROR, "Unknown exception: " + str(e))
                self._log(ERROR, util.tb_strings())
                self.saved_exception = e
            _active_threads.remove(self)
            for chan in list(self._channels.values()):
                chan._unlink()
            if self.active:
                self.active = False
                self.packetizer.close()
                if self.completion_event is not None:
                    self.completion_event.set()
                if self.auth_handler is not None:
                    self.auth_handler.abort()
                for event in self.channel_events.values():
                    event.set()
                try:
                    self.lock.acquire()
                    self.server_accept_cv.notify()
                finally:
                    self.lock.release()
            self.sock.close()
        except:
            # Don't raise spurious 'NoneType has no attribute X' errors when we
            # wake up during interpreter shutdown. Or rather -- raise
            # everything *if* sys.modules (used as a convenient sentinel)
            # appears to still exist.
            if self.sys.modules is not None:
                raise

    def _log_agreement(self, which, local, remote):
        # Log useful, non-duplicative line re: an agreed-upon algorithm.
        # Old code implied algorithms could be asymmetrical (different for
        # inbound vs outbound) so we preserve that possibility.
        msg = "{}: ".format(which)
        if local == remote:
            msg += local
        else:
            msg += "local={}, remote={}".format(local, remote)
        self._log(DEBUG, msg)

    # protocol stages

    def _negotiate_keys(self, m):
        # throws SSHException on anything unusual
        self.clear_to_send_lock.acquire()
        try:
            self.clear_to_send.clear()
        finally:
            self.clear_to_send_lock.release()
        if self.local_kex_init is None:
            # remote side wants to renegotiate
            self._send_kex_init()
        self._parse_kex_init(m)
        self.kex_engine.start_kex()

    def _check_banner(self):
        # this is slow, but we only have to do it once
        for i in range(100):
            # give them 15 seconds for the first line, then just 2 seconds
            # each additional line.  (some sites have very high latency.)
            if i == 0:
                timeout = self.banner_timeout
            else:
                timeout = 2
            try:
                buf = self.packetizer.readline(timeout)
            except ProxyCommandFailure:
                raise
            except Exception as e:
                raise SSHException(
                    "Error reading SSH protocol banner" + str(e)
                )
            if buf[:4] == "SSH-":
                break
            self._log(DEBUG, "Banner: " + buf)
        if buf[:4] != "SSH-":
            raise SSHException('Indecipherable protocol version "' + buf + '"')
        # save this server version string for later
        self.remote_version = buf
        self._log(DEBUG, "Remote version/idstring: {}".format(buf))
        # pull off any attached comment
        # NOTE: comment used to be stored in a variable and then...never used.
        # since 2003. ca 877cd974b8182d26fa76d566072917ea67b64e67
        i = buf.find(" ")
        if i >= 0:
            buf = buf[:i]
        # parse out version string and make sure it matches
        segs = buf.split("-", 2)
        if len(segs) < 3:
            raise SSHException("Invalid SSH banner")
        version = segs[1]
        client = segs[2]
        if version != "1.99" and version != "2.0":
            msg = "Incompatible version ({} instead of 2.0)"
            raise IncompatiblePeer(msg.format(version))
        msg = "Connected (version {}, client {})".format(version, client)
        self._log(INFO, msg)

    def _send_kex_init(self):
        """
        announce to the other side that we'd like to negotiate keys, and what
        kind of key negotiation we support.
        """
        self.clear_to_send_lock.acquire()
        try:
            self.clear_to_send.clear()
        finally:
            self.clear_to_send_lock.release()
        self.gss_kex_used = False
        self.in_kex = True
        kex_algos = list(self.preferred_kex)
        if self.server_mode:
            mp_required_prefix = "diffie-hellman-group-exchange-sha"
            kex_mp = [k for k in kex_algos if k.startswith(mp_required_prefix)]
            if (self._modulus_pack is None) and (len(kex_mp) > 0):
                # can't do group-exchange if we don't have a pack of potential
                # primes
                pkex = [
                    k
                    for k in self.get_security_options().kex
                    if not k.startswith(mp_required_prefix)
                ]
                self.get_security_options().kex = pkex
            available_server_keys = list(
                filter(
                    list(self.server_key_dict.keys()).__contains__,
                    # TODO: ensure tests will catch if somebody streamlines
                    # this by mistake - case is the admittedly silly one where
                    # the only calls to add_server_key() contain keys which
                    # were filtered out of the below via disabled_algorithms.
                    # If this is streamlined, we would then be allowing the
                    # disabled algorithm(s) for hostkey use
                    # TODO: honestly this prob just wants to get thrown out
                    # when we make kex configuration more straightforward
                    self.preferred_keys,
                )
            )
        else:
            available_server_keys = self.preferred_keys
            # Signal support for MSG_EXT_INFO so server will send it to us.
            # NOTE: doing this here handily means we don't even consider this
            # value when agreeing on real kex algo to use (which is a common
            # pitfall when adding this apparently).
            kex_algos.append("ext-info-c")

        # Similar to ext-info, but used in both server modes, so done outside
        # of above if/else.
        if self.advertise_strict_kex:
            which = "s" if self.server_mode else "c"
            kex_algos.append(f"kex-strict-{which}-v00@openssh.com")

        m = Message()
        m.add_byte(cMSG_KEXINIT)
        m.add_bytes(os.urandom(16))
        m.add_list(kex_algos)
        m.add_list(available_server_keys)
        m.add_list(self.preferred_ciphers)
        m.add_list(self.preferred_ciphers)
        m.add_list(self.preferred_macs)
        m.add_list(self.preferred_macs)
        m.add_list(self.preferred_compression)
        m.add_list(self.preferred_compression)
        m.add_string(bytes())
        m.add_string(bytes())
        m.add_boolean(False)
        m.add_int(0)
        # save a copy for later (needed to compute a hash)
        self.local_kex_init = self._latest_kex_init = m.asbytes()
        self._send_message(m)

    def _really_parse_kex_init(self, m, ignore_first_byte=False):
        parsed = {}
        if ignore_first_byte:
            m.get_byte()
        m.get_bytes(16)  # cookie, discarded
        parsed["kex_algo_list"] = m.get_list()
        parsed["server_key_algo_list"] = m.get_list()
        parsed["client_encrypt_algo_list"] = m.get_list()
        parsed["server_encrypt_algo_list"] = m.get_list()
        parsed["client_mac_algo_list"] = m.get_list()
        parsed["server_mac_algo_list"] = m.get_list()
        parsed["client_compress_algo_list"] = m.get_list()
        parsed["server_compress_algo_list"] = m.get_list()
        parsed["client_lang_list"] = m.get_list()
        parsed["server_lang_list"] = m.get_list()
        parsed["kex_follows"] = m.get_boolean()
        m.get_int()  # unused
        return parsed

    def _get_latest_kex_init(self):
        return self._really_parse_kex_init(
            Message(self._latest_kex_init),
            ignore_first_byte=True,
        )

    def _parse_kex_init(self, m):
        parsed = self._really_parse_kex_init(m)
        kex_algo_list = parsed["kex_algo_list"]
        server_key_algo_list = parsed["server_key_algo_list"]
        client_encrypt_algo_list = parsed["client_encrypt_algo_list"]
        server_encrypt_algo_list = parsed["server_encrypt_algo_list"]
        client_mac_algo_list = parsed["client_mac_algo_list"]
        server_mac_algo_list = parsed["server_mac_algo_list"]
        client_compress_algo_list = parsed["client_compress_algo_list"]
        server_compress_algo_list = parsed["server_compress_algo_list"]
        client_lang_list = parsed["client_lang_list"]
        server_lang_list = parsed["server_lang_list"]
        kex_follows = parsed["kex_follows"]

        self._log(DEBUG, "=== Key exchange possibilities ===")
        for prefix, value in (
            ("kex algos", kex_algo_list),
            ("server key", server_key_algo_list),
            # TODO: shouldn't these two lines say "cipher" to match usual
            # terminology (including elsewhere in paramiko!)?
            ("client encrypt", client_encrypt_algo_list),
            ("server encrypt", server_encrypt_algo_list),
            ("client mac", client_mac_algo_list),
            ("server mac", server_mac_algo_list),
            ("client compress", client_compress_algo_list),
            ("server compress", server_compress_algo_list),
            ("client lang", client_lang_list),
            ("server lang", server_lang_list),
        ):
            if value == [""]:
                value = ["<none>"]
            value = ", ".join(value)
            self._log(DEBUG, "{}: {}".format(prefix, value))
        self._log(DEBUG, "kex follows: {}".format(kex_follows))
        self._log(DEBUG, "=== Key exchange agreements ===")

        # Record, and strip out, ext-info and/or strict-kex non-algorithms
        self._remote_ext_info = None
        self._remote_strict_kex = None
        to_pop = []
        for i, algo in enumerate(kex_algo_list):
            if algo.startswith("ext-info-"):
                self._remote_ext_info = algo
                to_pop.insert(0, i)
            elif algo.startswith("kex-strict-"):
                # NOTE: this is what we are expecting from the /remote/ end.
                which = "c" if self.server_mode else "s"
                expected = f"kex-strict-{which}-v00@openssh.com"
                # Set strict mode if agreed.
                self.agreed_on_strict_kex = (
                    algo == expected and self.advertise_strict_kex
                )
                self._log(
                    DEBUG, f"Strict kex mode: {self.agreed_on_strict_kex}"
                )
                to_pop.insert(0, i)
        for i in to_pop:
            kex_algo_list.pop(i)

        # CVE mitigation: expect zeroed-out seqno anytime we are performing kex
        # init phase, if strict mode was negotiated.
        if (
            self.agreed_on_strict_kex
            and not self.initial_kex_done
            and m.seqno != 0
        ):
            raise MessageOrderError(
                "In strict-kex mode, but KEXINIT was not the first packet!"
            )

        # as a server, we pick the first item in the client's list that we
        # support.
        # as a client, we pick the first item in our list that the server
        # supports.
        if self.server_mode:
            agreed_kex = list(
                filter(self.preferred_kex.__contains__, kex_algo_list)
            )
        else:
            agreed_kex = list(
                filter(kex_algo_list.__contains__, self.preferred_kex)
            )
        if len(agreed_kex) == 0:
            # TODO: do an auth-overhaul style aggregate exception here?
            # TODO: would let us streamline log output & show all failures up
            # front
            raise IncompatiblePeer(
                "Incompatible ssh peer (no acceptable kex algorithm)"
            )  # noqa
        self.kex_engine = self._kex_info[agreed_kex[0]](self)
        self._log(DEBUG, "Kex: {}".format(agreed_kex[0]))

        if self.server_mode:
            available_server_keys = list(
                filter(
                    list(self.server_key_dict.keys()).__contains__,
                    self.preferred_keys,
                )
            )
            agreed_keys = list(
                filter(
                    available_server_keys.__contains__, server_key_algo_list
                )
            )
        else:
            agreed_keys = list(
                filter(server_key_algo_list.__contains__, self.preferred_keys)
            )
        if len(agreed_keys) == 0:
            raise IncompatiblePeer(
                "Incompatible ssh peer (no acceptable host key)"
            )  # noqa
        self.host_key_type = agreed_keys[0]
        if self.server_mode and (self.get_server_key() is None):
            raise IncompatiblePeer(
                "Incompatible ssh peer (can't match requested host key type)"
            )  # noqa
        self._log_agreement("HostKey", agreed_keys[0], agreed_keys[0])

        if self.server_mode:
            agreed_local_ciphers = list(
                filter(
                    self.preferred_ciphers.__contains__,
                    server_encrypt_algo_list,
                )
            )
            agreed_remote_ciphers = list(
                filter(
                    self.preferred_ciphers.__contains__,
                    client_encrypt_algo_list,
                )
            )
        else:
            agreed_local_ciphers = list(
                filter(
                    client_encrypt_algo_list.__contains__,
                    self.preferred_ciphers,
                )
            )
            agreed_remote_ciphers = list(
                filter(
                    server_encrypt_algo_list.__contains__,
                    self.preferred_ciphers,
                )
            )
        if len(agreed_local_ciphers) == 0 or len(agreed_remote_ciphers) == 0:
            raise IncompatiblePeer(
                "Incompatible ssh server (no acceptable ciphers)"
            )  # noqa
        self.local_cipher = agreed_local_ciphers[0]
        self.remote_cipher = agreed_remote_ciphers[0]
        self._log_agreement(
            "Cipher", local=self.local_cipher, remote=self.remote_cipher
        )

        if self.server_mode:
            agreed_remote_macs = list(
                filter(self.preferred_macs.__contains__, client_mac_algo_list)
            )
            agreed_local_macs = list(
                filter(self.preferred_macs.__contains__, server_mac_algo_list)
            )
        else:
            agreed_local_macs = list(
                filter(client_mac_algo_list.__contains__, self.preferred_macs)
            )
            agreed_remote_macs = list(
                filter(server_mac_algo_list.__contains__, self.preferred_macs)
            )
        if (len(agreed_local_macs) == 0) or (len(agreed_remote_macs) == 0):
            raise IncompatiblePeer(
                "Incompatible ssh server (no acceptable macs)"
            )
        self.local_mac = agreed_local_macs[0]
        self.remote_mac = agreed_remote_macs[0]
        self._log_agreement(
            "MAC", local=self.local_mac, remote=self.remote_mac
        )

        if self.server_mode:
            agreed_remote_compression = list(
                filter(
                    self.preferred_compression.__contains__,
                    client_compress_algo_list,
                )
            )
            agreed_local_compression = list(
                filter(
                    self.preferred_compression.__contains__,
                    server_compress_algo_list,
                )
            )
        else:
            agreed_local_compression = list(
                filter(
                    client_compress_algo_list.__contains__,
                    self.preferred_compression,
                )
            )
            agreed_remote_compression = list(
                filter(
                    server_compress_algo_list.__contains__,
                    self.preferred_compression,
                )
            )
        if (
            len(agreed_local_compression) == 0
            or len(agreed_remote_compression) == 0
        ):
            msg = "Incompatible ssh server (no acceptable compression)"
            msg += " {!r} {!r} {!r}"
            raise IncompatiblePeer(
                msg.format(
                    agreed_local_compression,
                    agreed_remote_compression,
                    self.preferred_compression,
                )
            )
        self.local_compression = agreed_local_compression[0]
        self.remote_compression = agreed_remote_compression[0]
        self._log_agreement(
            "Compression",
            local=self.local_compression,
            remote=self.remote_compression,
        )
        self._log(DEBUG, "=== End of kex handshake ===")

        # save for computing hash later...
        # now wait!  openssh has a bug (and others might too) where there are
        # actually some extra bytes (one NUL byte in openssh's case) added to
        # the end of the packet but not parsed.  turns out we need to throw
        # away those bytes because they aren't part of the hash.
        self.remote_kex_init = cMSG_KEXINIT + m.get_so_far()

    def _activate_inbound(self):
        """switch on newly negotiated encryption parameters for
        inbound traffic"""
        info = self._cipher_info[self.remote_cipher]
        aead = info.get("is_aead", False)
        block_size = info["block-size"]
        key_size = info["key-size"]
        # Non-AEAD/GCM type ciphers' IV size is their block size.
        iv_size = info.get("iv-size", block_size)
        if self.server_mode:
            iv_in = self._compute_key("A", iv_size)
            key_in = self._compute_key("C", key_size)
        else:
            iv_in = self._compute_key("B", iv_size)
            key_in = self._compute_key("D", key_size)

        engine = self._get_engine(
            name=self.remote_cipher,
            key=key_in,
            iv=iv_in,
            operation=self._DECRYPT,
            aead=aead,
        )
        etm = (not aead) and "etm@openssh.com" in self.remote_mac
        mac_size = self._mac_info[self.remote_mac]["size"]
        mac_engine = self._mac_info[self.remote_mac]["class"]
        # initial mac keys are done in the hash's natural size (not the
        # potentially truncated transmission size)
        if self.server_mode:
            mac_key = self._compute_key("E", mac_engine().digest_size)
        else:
            mac_key = self._compute_key("F", mac_engine().digest_size)

        self.packetizer.set_inbound_cipher(
            block_engine=engine,
            block_size=block_size,
            mac_engine=None if aead else mac_engine,
            mac_size=16 if aead else mac_size,
            mac_key=None if aead else mac_key,
            etm=etm,
            aead=aead,
            iv_in=iv_in if aead else None,
        )

        compress_in = self._compression_info[self.remote_compression][1]
        if compress_in is not None and (
            self.remote_compression != "zlib@openssh.com" or self.authenticated
        ):
            self._log(DEBUG, "Switching on inbound compression ...")
            self.packetizer.set_inbound_compressor(compress_in())
        # Reset inbound sequence number if strict mode.
        if self.agreed_on_strict_kex:
            self._log(
                DEBUG,
                "Resetting inbound seqno after NEWKEYS due to strict mode",
            )
            self.packetizer.reset_seqno_in()

    def _activate_outbound(self):
        """switch on newly negotiated encryption parameters for
        outbound traffic"""
        m = Message()
        m.add_byte(cMSG_NEWKEYS)
        self._send_message(m)
        # Reset outbound sequence number if strict mode.
        if self.agreed_on_strict_kex:
            self._log(
                DEBUG,
                "Resetting outbound seqno after NEWKEYS due to strict mode",
            )
            self.packetizer.reset_seqno_out()
        info = self._cipher_info[self.local_cipher]
        aead = info.get("is_aead", False)
        block_size = info["block-size"]
        key_size = info["key-size"]
        # Non-AEAD/GCM type ciphers' IV size is their block size.
        iv_size = info.get("iv-size", block_size)
        if self.server_mode:
            iv_out = self._compute_key("B", iv_size)
            key_out = self._compute_key("D", key_size)
        else:
            iv_out = self._compute_key("A", iv_size)
            key_out = self._compute_key("C", key_size)

        engine = self._get_engine(
            name=self.local_cipher,
            key=key_out,
            iv=iv_out,
            operation=self._ENCRYPT,
            aead=aead,
        )
        etm = (not aead) and "etm@openssh.com" in self.local_mac
        mac_size = self._mac_info[self.local_mac]["size"]
        mac_engine = self._mac_info[self.local_mac]["class"]
        # initial mac keys are done in the hash's natural size (not the
        # potentially truncated transmission size)
        if self.server_mode:
            mac_key = self._compute_key("F", mac_engine().digest_size)
        else:
            mac_key = self._compute_key("E", mac_engine().digest_size)
        sdctr = self.local_cipher.endswith("-ctr")

        self.packetizer.set_outbound_cipher(
            block_engine=engine,
            block_size=block_size,
            mac_engine=None if aead else mac_engine,
            mac_size=16 if aead else mac_size,
            mac_key=None if aead else mac_key,
            sdctr=sdctr,
            etm=etm,
            aead=aead,
            iv_out=iv_out if aead else None,
        )

        compress_out = self._compression_info[self.local_compression][0]
        if compress_out is not None and (
            self.local_compression != "zlib@openssh.com" or self.authenticated
        ):
            self._log(DEBUG, "Switching on outbound compression ...")
            self.packetizer.set_outbound_compressor(compress_out())
        if not self.packetizer.need_rekey():
            self.in_kex = False
        # If client indicated extension support, send that packet immediately
        if (
            self.server_mode
            and self.server_sig_algs
            and self._remote_ext_info == "ext-info-c"
        ):
            extensions = {"server-sig-algs": ",".join(self.preferred_pubkeys)}
            m = Message()
            m.add_byte(cMSG_EXT_INFO)
            m.add_int(len(extensions))
            for name, value in sorted(extensions.items()):
                m.add_string(name)
                m.add_string(value)
            self._send_message(m)
        # we always expect to receive NEWKEYS now
        self._expect_packet(MSG_NEWKEYS)

    def _auth_trigger(self):
        self.authenticated = True
        # delayed initiation of compression
        if self.local_compression == "zlib@openssh.com":
            compress_out = self._compression_info[self.local_compression][0]
            self._log(DEBUG, "Switching on outbound compression ...")
            self.packetizer.set_outbound_compressor(compress_out())
        if self.remote_compression == "zlib@openssh.com":
            compress_in = self._compression_info[self.remote_compression][1]
            self._log(DEBUG, "Switching on inbound compression ...")
            self.packetizer.set_inbound_compressor(compress_in())

    def _parse_ext_info(self, msg):
        # Packet is a count followed by that many key-string to possibly-bytes
        # pairs.
        extensions = {}
        for _ in range(msg.get_int()):
            name = msg.get_text()
            value = msg.get_string()
            extensions[name] = value
        self._log(DEBUG, "Got EXT_INFO: {}".format(extensions))
        # NOTE: this should work ok in cases where a server sends /two/ such
        # messages; the RFC explicitly states a 2nd one should overwrite the
        # 1st.
        self.server_extensions = extensions

    def _parse_newkeys(self, m):
        self._log(DEBUG, "Switch to new keys ...")
        self._activate_inbound()
        # can also free a bunch of stuff here
        self.local_kex_init = self.remote_kex_init = None
        self.K = None
        self.kex_engine = None
        if self.server_mode and (self.auth_handler is None):
            # create auth handler for server mode
            self.auth_handler = AuthHandler(self)
        if not self.initial_kex_done:
            # this was the first key exchange
            # (also signal to packetizer as it sometimes wants to know this
            # status as well, eg when seqnos rollover)
            self.initial_kex_done = self.packetizer._initial_kex_done = True
        # send an event?
        if self.completion_event is not None:
            self.completion_event.set()
        # it's now okay to send data again (if this was a re-key)
        if not self.packetizer.need_rekey():
            self.in_kex = False
        self.clear_to_send_lock.acquire()
        try:
            self.clear_to_send.set()
        finally:
            self.clear_to_send_lock.release()
        return

    def _parse_disconnect(self, m):
        code = m.get_int()
        desc = m.get_text()
        self._log(INFO, "Disconnect (code {:d}): {}".format(code, desc))

    def _parse_global_request(self, m):
        kind = m.get_text()
        self._log(DEBUG, 'Received global request "{}"'.format(kind))
        want_reply = m.get_boolean()
        if not self.server_mode:
            self._log(
                DEBUG,
                'Rejecting "{}" global request from server.'.format(kind),
            )
            ok = False
        elif kind == "tcpip-forward":
            address = m.get_text()
            port = m.get_int()
            ok = self.server_object.check_port_forward_request(address, port)
            if ok:
                ok = (ok,)
        elif kind == "cancel-tcpip-forward":
            address = m.get_text()
            port = m.get_int()
            self.server_object.cancel_port_forward_request(address, port)
            ok = True
        else:
            ok = self.server_object.check_global_request(kind, m)
        extra = ()
        if type(ok) is tuple:
            extra = ok
            ok = True
        if want_reply:
            msg = Message()
            if ok:
                msg.add_byte(cMSG_REQUEST_SUCCESS)
                msg.add(*extra)
            else:
                msg.add_byte(cMSG_REQUEST_FAILURE)
            self._send_message(msg)

    def _parse_request_success(self, m):
        self._log(DEBUG, "Global request successful.")
        self.global_response = m
        if self.completion_event is not None:
            self.completion_event.set()

    def _parse_request_failure(self, m):
        self._log(DEBUG, "Global request denied.")
        self.global_response = None
        if self.completion_event is not None:
            self.completion_event.set()

    def _parse_channel_open_success(self, m):
        chanid = m.get_int()
        server_chanid = m.get_int()
        server_window_size = m.get_int()
        server_max_packet_size = m.get_int()
        chan = self._channels.get(chanid)
        if chan is None:
            self._log(WARNING, "Success for unrequested channel! [??]")
            return
        self.lock.acquire()
        try:
            chan._set_remote_channel(
                server_chanid, server_window_size, server_max_packet_size
            )
            self._log(DEBUG, "Secsh channel {:d} opened.".format(chanid))
            if chanid in self.channel_events:
                self.channel_events[chanid].set()
                del self.channel_events[chanid]
        finally:
            self.lock.release()
        return

    def _parse_channel_open_failure(self, m):
        chanid = m.get_int()
        reason = m.get_int()
        reason_str = m.get_text()
        m.get_text()  # ignored language
        reason_text = CONNECTION_FAILED_CODE.get(reason, "(unknown code)")
        self._log(
            ERROR,
            "Secsh channel {:d} open FAILED: {}: {}".format(
                chanid, reason_str, reason_text
            ),
        )
        self.lock.acquire()
        try:
            self.saved_exception = ChannelException(reason, reason_text)
            if chanid in self.channel_events:
                self._channels.delete(chanid)
                if chanid in self.channel_events:
                    self.channel_events[chanid].set()
                    del self.channel_events[chanid]
        finally:
            self.lock.release()
        return

    def _parse_channel_open(self, m):
        kind = m.get_text()
        chanid = m.get_int()
        initial_window_size = m.get_int()
        max_packet_size = m.get_int()
        reject = False
        if (
            kind == "auth-agent@openssh.com"
            and self._forward_agent_handler is not None
        ):
            self._log(DEBUG, "Incoming forward agent connection")
            self.lock.acquire()
            try:
                my_chanid = self._next_channel()
            finally:
                self.lock.release()
        elif (kind == "x11") and (self._x11_handler is not None):
            origin_addr = m.get_text()
            origin_port = m.get_int()
            self._log(
                DEBUG,
                "Incoming x11 connection from {}:{:d}".format(
                    origin_addr, origin_port
                ),
            )
            self.lock.acquire()
            try:
                my_chanid = self._next_channel()
            finally:
                self.lock.release()
        elif (kind == "forwarded-tcpip") and (self._tcp_handler is not None):
            server_addr = m.get_text()
            server_port = m.get_int()
            origin_addr = m.get_text()
            origin_port = m.get_int()
            self._log(
                DEBUG,
                "Incoming tcp forwarded connection from {}:{:d}".format(
                    origin_addr, origin_port
                ),
            )
            self.lock.acquire()
            try:
                my_chanid = self._next_channel()
            finally:
                self.lock.release()
        elif not self.server_mode:
            self._log(
                DEBUG,
                'Rejecting "{}" channel request from server.'.format(kind),
            )
            reject = True
            reason = OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        else:
            self.lock.acquire()
            try:
                my_chanid = self._next_channel()
            finally:
                self.lock.release()
            if kind == "direct-tcpip":
                # handle direct-tcpip requests coming from the client
                dest_addr = m.get_text()
                dest_port = m.get_int()
                origin_addr = m.get_text()
                origin_port = m.get_int()
                reason = self.server_object.check_channel_direct_tcpip_request(
                    my_chanid,
                    (origin_addr, origin_port),
                    (dest_addr, dest_port),
                )
            else:
                reason = self.server_object.check_channel_request(
                    kind, my_chanid
                )
            if reason != OPEN_SUCCEEDED:
                self._log(
                    DEBUG,
                    'Rejecting "{}" channel request from client.'.format(kind),
                )
                reject = True
        if reject:
            msg = Message()
            msg.add_byte(cMSG_CHANNEL_OPEN_FAILURE)
            msg.add_int(chanid)
            msg.add_int(reason)
            msg.add_string("")
            msg.add_string("en")
            self._send_message(msg)
            return

        chan = Channel(my_chanid)
        self.lock.acquire()
        try:
            self._channels.put(my_chanid, chan)
            self.channels_seen[my_chanid] = True
            chan._set_transport(self)
            chan._set_window(
                self.default_window_size, self.default_max_packet_size
            )
            chan._set_remote_channel(
                chanid, initial_window_size, max_packet_size
            )
        finally:
            self.lock.release()
        m = Message()
        m.add_byte(cMSG_CHANNEL_OPEN_SUCCESS)
        m.add_int(chanid)
        m.add_int(my_chanid)
        m.add_int(self.default_window_size)
        m.add_int(self.default_max_packet_size)
        self._send_message(m)
        self._log(
            DEBUG, "Secsh channel {:d} ({}) opened.".format(my_chanid, kind)
        )
        if kind == "auth-agent@openssh.com":
            self._forward_agent_handler(chan)
        elif kind == "x11":
            self._x11_handler(chan, (origin_addr, origin_port))
        elif kind == "forwarded-tcpip":
            chan.origin_addr = (origin_addr, origin_port)
            self._tcp_handler(
                chan, (origin_addr, origin_port), (server_addr, server_port)
            )
        else:
            self._queue_incoming_channel(chan)

    def _parse_debug(self, m):
        m.get_boolean()  # always_display
        msg = m.get_string()
        m.get_string()  # language
        self._log(DEBUG, "Debug msg: {}".format(util.safe_string(msg)))

    def _get_subsystem_handler(self, name):
        try:
            self.lock.acquire()
            if name not in self.subsystem_table:
                return None, [], {}
            return self.subsystem_table[name]
        finally:
            self.lock.release()

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


# TODO 4.0: drop this, we barely use it ourselves, it badly replicates the
# Transport-internal algorithm management, AND does so in a way which doesn't
# honor newer things like disabled_algorithms!
class SecurityOptions:
    """
    Simple object containing the security preferences of an ssh transport.
    These are tuples of acceptable ciphers, digests, key types, and key
    exchange algorithms, listed in order of preference.

    Changing the contents and/or order of these fields affects the underlying
    `.Transport` (but only if you change them before starting the session).
    If you try to add an algorithm that paramiko doesn't recognize,
    ``ValueError`` will be raised.  If you try to assign something besides a
    tuple to one of the fields, ``TypeError`` will be raised.
    """

    __slots__ = "_transport"

    def __init__(self, transport):
        self._transport = transport

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.
        """
        return "<paramiko.SecurityOptions for {!r}>".format(self._transport)

    def _set(self, name, orig, x):
        if type(x) is list:
            x = tuple(x)
        if type(x) is not tuple:
            raise TypeError("expected tuple or list")
        possible = list(getattr(self._transport, orig).keys())
        forbidden = [n for n in x if n not in possible]
        if len(forbidden) > 0:
            raise ValueError("unknown cipher")
        setattr(self._transport, name, x)

    @property
    def ciphers(self):
        """Symmetric encryption ciphers"""
        return self._transport._preferred_ciphers

    @ciphers.setter
    def ciphers(self, x):
        self._set("_preferred_ciphers", "_cipher_info", x)

    @property
    def digests(self):
        """Digest (one-way hash) algorithms"""
        return self._transport._preferred_macs

    @digests.setter
    def digests(self, x):
        self._set("_preferred_macs", "_mac_info", x)

    @property
    def key_types(self):
        """Public-key algorithms"""
        return self._transport._preferred_keys

    @key_types.setter
    def key_types(self, x):
        self._set("_preferred_keys", "_key_info", x)

    @property
    def kex(self):
        """Key exchange algorithms"""
        return self._transport._preferred_kex

    @kex.setter
    def kex(self, x):
        self._set("_preferred_kex", "_kex_info", x)

    @property
    def compression(self):
        """Compression algorithms"""
        return self._transport._preferred_compression

    @compression.setter
    def compression(self, x):
        self._set("_preferred_compression", "_compression_info", x)


class ChannelMap:
    def __init__(self):
        # (id -> Channel)
        self._map = weakref.WeakValueDictionary()
        self._lock = threading.Lock()

    def put(self, chanid, chan):
        self._lock.acquire()
        try:
            self._map[chanid] = chan
        finally:
            self._lock.release()

    def get(self, chanid):
        self._lock.acquire()
        try:
            return self._map.get(chanid, None)
        finally:
            self._lock.release()

    def delete(self, chanid):
        self._lock.acquire()
        try:
            try:
                del self._map[chanid]
            except KeyError:
                pass
        finally:
            self._lock.release()

    def values(self):
        self._lock.acquire()
        try:
            return list(self._map.values())
        finally:
            self._lock.release()

    def __len__(self):
        self._lock.acquire()
        try:
            return len(self._map)
        finally:
            self._lock.release()


class ServiceRequestingTransport(Transport):
    """
    Transport, but also handling service requests, like it oughtta!

    .. versionadded:: 3.2
    """

    # NOTE: this purposefully duplicates some of the parent class in order to
    # modernize, refactor, etc. The intent is that eventually we will collapse
    # this one onto the parent in a backwards incompatible release.

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._service_userauth_accepted = False
        self._handler_table[MSG_SERVICE_ACCEPT] = self._parse_service_accept

    def _parse_service_accept(self, m):
        service = m.get_text()
        # Short-circuit for any service name not ssh-userauth.
        # NOTE: it's technically possible for 'service name' in
        # SERVICE_REQUEST/ACCEPT messages to be "ssh-connection" --
        # but I don't see evidence of Paramiko ever initiating or expecting to
        # receive one of these. We /do/ see the 'service name' field in
        # MSG_USERAUTH_REQUEST/ACCEPT/FAILURE set to this string, but that is a
        # different set of handlers, so...!
        if service != "ssh-userauth":
            # TODO 4.0: consider erroring here (with an ability to opt out?)
            # instead as it probably means something went Very Wrong.
            self._log(
                DEBUG, 'Service request "{}" accepted (?)'.format(service)
            )
            return
        # Record that we saw a service-userauth acceptance, meaning we are free
        # to submit auth requests.
        self._service_userauth_accepted = True
        self._log(DEBUG, "MSG_SERVICE_ACCEPT received; auth may begin")

    def ensure_session(self):
        # Make sure we're not trying to auth on a not-yet-open or
        # already-closed transport session; that's our responsibility, not that
        # of AuthHandler.
        if (not self.active) or (not self.initial_kex_done):
            # TODO: better error message? this can happen in many places, eg
            # user error (authing before connecting) or developer error (some
            # improperly handled pre/mid auth shutdown didn't become fatal
            # enough). The latter is much more common & should ideally be fixed
            # by terminating things harder?
            raise SSHException("No existing session")
        # Also make sure we've actually been told we are allowed to auth.
        if self._service_userauth_accepted:
            return
        # Or request to do so, otherwise.
        m = Message()
        m.add_byte(cMSG_SERVICE_REQUEST)
        m.add_string("ssh-userauth")
        self._log(DEBUG, "Sending MSG_SERVICE_REQUEST: ssh-userauth")
        self._send_message(m)
        # Now we wait to hear back; the user is expecting a blocking-style auth
        # request so there's no point giving control back anywhere.
        while not self._service_userauth_accepted:
            # TODO: feels like we're missing an AuthHandler Event like
            # 'self.auth_event' which is set when AuthHandler shuts down in
            # ways good AND bad. Transport only seems to have completion_event
            # which is unclear re: intent, eg it's set by newkeys which always
            # happens on connection, so it'll always be set by the time we get
            # here.
            # NOTE: this copies the timing of event.wait() in
            # AuthHandler.wait_for_response, re: 1/10 of a second. Could
            # presumably be smaller, but seems unlikely this period is going to
            # be "too long" for any code doing ssh networking...
            time.sleep(0.1)
        self.auth_handler = self.get_auth_handler()

    def get_auth_handler(self):
        # NOTE: using new sibling subclass instead of classic AuthHandler
        return AuthOnlyHandler(self)

    def auth_none(self, username):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        self.ensure_session()
        return self.auth_handler.auth_none(username)

    def auth_password(self, username, password, fallback=True):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        self.ensure_session()
        try:
            return self.auth_handler.auth_password(username, password)
        except BadAuthenticationType as e:
            # if password auth isn't allowed, but keyboard-interactive *is*,
            # try to fudge it
            if not fallback or ("keyboard-interactive" not in e.allowed_types):
                raise
            try:

                def handler(title, instructions, fields):
                    if len(fields) > 1:
                        raise SSHException("Fallback authentication failed.")
                    if len(fields) == 0:
                        # for some reason, at least on os x, a 2nd request will
                        # be made with zero fields requested.  maybe it's just
                        # to try to fake out automated scripting of the exact
                        # type we're doing here.  *shrug* :)
                        return []
                    return [password]

                return self.auth_interactive(username, handler)
            except SSHException:
                # attempt to fudge failed; just raise the original exception
                raise e

    def auth_publickey(self, username, key):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        self.ensure_session()
        return self.auth_handler.auth_publickey(username, key)

    def auth_interactive(self, username, handler, submethods=""):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        self.ensure_session()
        return self.auth_handler.auth_interactive(
            username, handler, submethods
        )

    def auth_interactive_dumb(self, username, handler=None, submethods=""):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        # NOTE: legacy impl omitted equiv of ensure_session since it just wraps
        # another call to an auth method. however we reinstate it for
        # consistency reasons.
        self.ensure_session()
        if not handler:

            def handler(title, instructions, prompt_list):
                answers = []
                if title:
                    print(title.strip())
                if instructions:
                    print(instructions.strip())
                for prompt, show_input in prompt_list:
                    print(prompt.strip(), end=" ")
                    answers.append(input())
                return answers

        return self.auth_interactive(username, handler, submethods)

    def auth_gssapi_with_mic(self, username, gss_host, gss_deleg_creds):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        self.ensure_session()
        self.auth_handler = self.get_auth_handler()
        return self.auth_handler.auth_gssapi_with_mic(
            username, gss_host, gss_deleg_creds
        )

    def auth_gssapi_keyex(self, username):
        # TODO 4.0: merge to parent, preserving (most of) docstring
        self.ensure_session()
        self.auth_handler = self.get_auth_handler()
        return self.auth_handler.auth_gssapi_keyex(username)
