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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
SOCKS5 server implementation.
"""

from errno import ECONNREFUSED, EHOSTUNREACH, ENETDOWN, ENETUNREACH

import select
import socket
import struct
import threading

try:
    from socketserver import StreamRequestHandler, ThreadingTCPServer
except ImportError:
    from SocketServer import StreamRequestHandler, ThreadingTCPServer

from paramiko.common import DEBUG, asbytes
from paramiko.py3compat import BytesIO, byte_chr, byte_ord, u
from paramiko.ssh_exception import NoValidConnectionsError
from paramiko.util import (
    families_and_addresses,
    get_logger,
    ip_addr_to_str,
    ClosingContextManager
)


SOCKS5_VERSION = 0x05

SOCKS5_CMD_CONNECT = 0x01

SOCKS5_NO_AUTH_REQUIRED = 0x00
SOCKS5_NO_ACCEPTABLE_METHOD = 0xff

SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV6 = 0x04

SOCKS5_RESERVED = 0x00

SOCKS5_SUCCEEDED = 0x00
SOCKS5_GENERAL_SERVER_FAILURE = 0x01
SOCKS5_CONNECTION_NOT_ALLOWED = 0x02
SOCKS5_NETWORK_UNREACHABLE = 0x03
SOCKS5_HOST_UNREACHABLE = 0x04
SOCKS5_CONNECTION_REFUSED = 0x05
SOCKS5_TTL_EXPIRED = 0x06
SOCKS5_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class SOCKSMessage:
    """
    An SOCKS message is a stream of bytes that encodes some combination of
    strings, integers and unsigned shorts. This class builds or breaks down
    such a byte stream.

    Normally you don't need to deal with anything this low-level, but it's
    exposed for people implementing custom extensions, or features that
    paramiko doesn't support yet.
    """

    def __init__(self, sock=None):
        """
        Create a new SOCKS message.

        :param socket.socket sock:
            socket object to read the message content from (passed in only when
            decomposing a message).
        """
        if sock is not None:
            self.packet = sock.makefile(mode="b")
        else:
            self.packet = BytesIO()

    def __str__(self):
        """
        Return the byte stream content of this message, as a string/bytes obj.

        :rtype: str
        """
        return u(self.asbytes())

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.

        :rtype: str
        """
        return "<paramiko.SOCKSMessage(" + repr(self.packet.getvalue()) + ")>"

    def asbytes(self):
        """
        Return the byte stream content of this Message, as bytes.

        :rtype: bytearray
        """
        return self.packet.getvalue()

    def get_bytes(self, n):
        """
        Return the next ``n`` bytes of the message (as a `str`), without
        decomposing into an int, decoded string, etc. Just the raw bytes are
        returned.

        :param int n: Number of bytes to get.

        :rtype: bytearray
        """
        return self.packet.read(n)

    def get_short(self):
        """
        Fetch an unsigned short from the stream.

        This is used for network ports in SOCKS messages.

        :rtype: int
        """
        return struct.unpack("!H", self.get_bytes(2))[0]

    def get_int(self):
        """
        Fetch an int from the stream.

        This is used for IPv4 IP addresses in SOCKS messages.

        :rtype: int
        """
        return struct.unpack("!I", self.get_bytes(4))[0]

    def get_int64(self):
        """
        Fetch a 64-bit int from the stream.

        Two of such int64 are used for IPv6 IP addresses in SOCKS messages.

        :return: a 64-bit unsigned integer (`long`).
        :rtype: int
        """
        return struct.unpack("!Q", self.get_bytes(8))[0]

    def get_char(self):
        """
        Fetch a single character from the stream and return its decoded value.
        """
        return byte_ord(struct.unpack("!c", self.get_bytes(1))[0])

    def get_string(self):
        """
        Fetch a Unicode string from the stream.

        Strings are used in SOCKS messages for the host name of the
        destination when the domain name address type is used.

        :rtype: str
        """
        return u(self.get_bytes(self.get_char()))

    def add_bytes(self, b):
        """
        Write bytes to the stream, without any formatting.

        :param str b: bytes to add

        :rtype: SOCKSMessage
        """
        self.packet.write(b)
        return self

    def add_short(self, n):
        """
        Add an unsigned short to the stream.

        :param int n: short to add

        :rtype: SOCKSMessage
        """
        self.packet.write(struct.pack("!H", n))
        return self

    def add_int(self, n):
        """
        Add an integer to the stream.

        This is used for IPv4 IP addresses in SOCKS messages.

        :param int n: integer to add

        :rtype: SOCKSMessage
        """
        self.packet.write(struct.pack("!I", n))
        return self

    def add_int64(self, n):
        """
        Add a 64-bit int to the stream.

        Two of such int64 are used for IPv6 IP addresses in SOCKS messages.

        :param long n: long int to add

        :rtype: SOCKSMessage
        """
        self.packet.write(struct.pack("!Q", n))
        return self

    def add_char(self, c):
        """
        Add a char to the stream

        :param c: character to add

        :rtype: SOCKSMessage
        """
        self.packet.write(byte_chr(c))
        return self

    def add_string(self, s):
        """
        Add a string to the stream.

        Strings are used in SOCKS messages for the host name of the
        destination when the domain name address type is used.

        :param str s: string to add

        :rtype: SOCKSMessage
        """
        s = asbytes(s)
        self.add_char(len(s))
        self.packet.write(s)
        return self


class SOCKS5RequestHandler(StreamRequestHandler, object):
    """
    Request handler for SOCKS5 requests.
    """

    def __init__(self, *args, **kwargs):
        self.logger = get_logger("paramiko.socks")
        super(SOCKS5RequestHandler, self).__init__(*args, **kwargs)

    def handle(self):
        """
        Handle incoming SOCKS requests.

        This parses incoming SOCKS requests, establishes a new "direct-tcpip"
        channel for each request and passes request and response data over the
        channel.
        """
        self._log(
            DEBUG,
            "Accepting connection from {}".format(
                ip_addr_to_str(self.client_address)
            )
        )

        m = SOCKSMessage(self.request)
        version = m.get_char()
        num_methods = m.get_char()

        if version != SOCKS5_VERSION:
            self._log(
                DEBUG,
                "Request for unsupported SOCKS version {}".format(version)
            )
            self._send_response(status=SOCKS5_GENERAL_SERVER_FAILURE)
            return

        auth_methods = {m.get_char() for _ in range(num_methods)}

        if SOCKS5_NO_AUTH_REQUIRED not in auth_methods:
            m = SOCKSMessage()
            m.add_char(SOCKS5_VERSION)
            m.add_char(SOCKS5_NO_ACCEPTABLE_METHOD)
            self.request.sendall(m.asbytes())
            return

        m = SOCKSMessage()
        m.add_char(SOCKS5_VERSION)
        m.add_char(SOCKS5_NO_AUTH_REQUIRED)
        self.request.sendall(m.asbytes())

        m = SOCKSMessage(self.request)
        version = m.get_char()
        cmd = m.get_char()
        rsv = m.get_char()
        address_type = m.get_char()

        if version != SOCKS5_VERSION:
            self._send_response(status=SOCKS5_GENERAL_SERVER_FAILURE)
            return

        if cmd != SOCKS5_CMD_CONNECT:
            self._send_response(status=SOCKS5_COMMAND_NOT_SUPPORTED)
            return

        if rsv != SOCKS5_RESERVED:
            self._send_response(status=SOCKS5_GENERAL_SERVER_FAILURE)
            return

        if address_type == SOCKS5_ATYP_IPV4:
            address = socket.inet_ntoa(m.get_bytes(4))
            port = m.get_short()
            af_and_addrs = [(socket.AF_INET, (address, port))]
        elif address_type == SOCKS5_ATYP_DOMAINNAME:
            hostname = m.get_string()
            port = m.get_short()
            af_and_addrs = families_and_addresses(hostname, port)
        elif address_type == SOCKS5_ATYP_IPV6:
            address = socket.inet_ntop(socket.AF_INET6, m.get_bytes(16))
            port = m.get_short()
            af_and_addrs = [(socket.AF_INET6, (address, port))]
        else:
            self._send_response(status=SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED)
            return

        channel = None
        try:
            channel, af, addr = self._open_channel(af_and_addrs)
        except NoValidConnectionsError as e:
            self._log(DEBUG, str(e))
            self._send_response(status=SOCKS5_GENERAL_SERVER_FAILURE)
            return
        except socket.error as e:
            if e.errno == ECONNREFUSED:
                self._send_response(status=SOCKS5_CONNECTION_REFUSED)
            elif e.errno == EHOSTUNREACH:
                self._send_response(status=SOCKS5_HOST_UNREACHABLE)
            elif e.errno in (ENETDOWN, ENETUNREACH):
                self._send_response(status=SOCKS5_NETWORK_UNREACHABLE)
            else:
                self._send_response(status=SOCKS5_GENERAL_SERVER_FAILURE)
            return
        else:
            self._log(
                DEBUG,
                "Established direct-tcpip channel with {}".format(
                    ip_addr_to_str(addr)
                )
            )

            self._send_response(af, addr)

            self._forward_data(self.request, channel)
        finally:
            if channel:
                channel.close()

    def _open_channel(self, fa):
        """
        :param fa: list of pairs of address families and addresses to try for
                   connecting.
        :raises: socket.error: if a socket error occurred while connecting
        :raises:
            `.NoValidConnectionsError` - if there was any other error
            connecting or establishing a channel
        """

        errors = {}
        for af, addr in fa:
            try:
                channel = self.server.ssh_transport.open_channel(
                    "direct-tcpip",
                    dest_addr=addr,
                    src_addr=self.request.getpeername()
                )
                return channel, af, addr
            except socket.error as e:
                # Raise anything that isn't a straight up connection error
                # (such as a resolution error)
                if e.errno not in (ECONNREFUSED, EHOSTUNREACH):
                    raise
                # Capture anything else so we know how the run looks once
                # iteration is complete. Retain info about which attempt
                # this was.
                errors[addr] = e

        # Make sure we explode usefully if no address family attempts
        # succeeded. We've no way of knowing which error is the "right"
        # one, so we construct a hybrid exception containing all the real
        # ones, of a subclass that client code should still be watching for
        # (socket.error)
        if errors:
            raise NoValidConnectionsError(errors)

    def _send_response(self, af=None, addr=None, status=SOCKS5_SUCCEEDED):
        """
        Send a response for a SOCKS connection request.

        :param af:
        :param tuple(str, int) addr: address tuple
        :param status:
        """
        m = SOCKSMessage()
        m.add_char(SOCKS5_VERSION)
        m.add_char(status)
        m.add_char(SOCKS5_RESERVED)

        if not af or not addr:
            m.add_char(SOCKS5_ATYP_IPV4)
            m.add_int(0)
            m.add_short(0)
        elif af == socket.AF_INET:
            addr_unpacked = struct.unpack("!I", socket.inet_aton(addr[0]))[0]
            m.add_char(SOCKS5_ATYP_IPV4)
            m.add_int(addr_unpacked)
            m.add_short(addr[1])
        else:
            hi, lo = struct.unpack(
                "!QQ",
                socket.inet_pton(socket.AF_INET6, addr[0])
            )
            m.add_char(SOCKS5_ATYP_IPV6)
            m.add_int64(hi)
            m.add_int64(lo)
            m.add_short(addr[1])

        self.request.sendall(m.asbytes())

    def _forward_data(self, socks_client, channel):
        """
        Pass data between the SOCKS client and the TCP endpoint on the
        other side of the SSH channel.

        :param .SocketType socks_client: Socket used by the requesting client
        :param .Channel channel: SSH channel to the destination
        """
        buf_size = 4096

        while True:
            r, _, _ = select.select([socks_client, channel], [], [])

            if socks_client in r:
                if channel.send(socks_client.recv(buf_size)) <= 0:
                    break

            if channel in r:
                if socks_client.send(channel.recv(buf_size)) <= 0:
                    break

    def _log(self, level, msg, *args):
        self.logger.log(level, msg, *args)


class IPv6EnabledTCPServer(ThreadingTCPServer, object):
    """
    Threaded TCP server with support for IPv6 in addition to IPv4.
    """

    daemon_threads = True
    allow_reuse_address = True
    ssh_transport = None

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        bind_and_activate=True
    ):
        """
        Custom init method for TCPServer, adding support for IPv6.

        :param tuple(str,int) server_address: tuple with the address to bind
            the server to
        :param RequestHandlerClass: class to use for handling requests
        :param bool bind_and_activate: whether to bind and activate the socket
            directly after initialization
        """
        af_and_addr = next(
            families_and_addresses(*server_address),
            None
        )
        if af_and_addr:
            self.address_family, server_address = af_and_addr
        super(IPv6EnabledTCPServer, self).__init__(
            server_address,
            RequestHandlerClass,
            bind_and_activate
        )


class SOCKSProxy(ClosingContextManager):
    """
    Provides a SOCKS5 proxy.

    Instances of this class may be used as context managers.
    """

    def __init__(self, transport, bind_address="localhost", port=1080):
        """
        Start a SOCKS proxy and make it available on a local socket.

        :param .Transport transport: an open `.Transport` which is already
            authenticated
        :param str bind_address: the interface to bind to
        :param int port: the port to bind to. Use 0 if you want to use a
            random, unused port
        """
        self.server = IPv6EnabledTCPServer(
            (bind_address, port), SOCKS5RequestHandler
        )
        self.server.ssh_transport = transport
        threading.Thread(target=self.server.serve_forever).start()

    def close(self):
        """
        Close the SOCKS proxy and its underlying channel.
        """
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def get_address(self):
        """
        Return a tuple with address and port the proxy is bound to.

        :return: tuple containing the address the SOCKS proxy is bound to
        :rtype: tuple(str, int)
        """
        return self.server.server_address

    def __repr__(self):
        """
        Return a string representation of the proxy.

        :return: string representation of the proxy
        :rtype: str
        """
        return "<paramiko.SOCKSProxy({})>".format(
            ip_addr_to_str(self.get_address())
        )
