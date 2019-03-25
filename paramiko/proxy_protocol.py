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

import binascii
import collections
import socket
import struct

from paramiko.common import DEBUG
from paramiko.py3compat import b2s, byte_ord
from paramiko.util import get_logger


PP_V1_SIGNATURE = b"PROXY"
PP_V1_ADDRESS_FAMILIES = {
    b"TCP4": socket.AF_INET,
    b"TCP6": socket.AF_INET6,
    b"UNKNOWN": socket.AF_UNSPEC,
}
PP_V1_CRLF = b"\r\n"

PP_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PP_V2_VERSION = 0x20
PP_V2_COMMANDS = {0: "LOCAL", 1: "PROXY"}
PP_V2_ADDRESS_FAMILIES = {
    0: socket.AF_UNSPEC,
    16: socket.AF_INET,
    32: socket.AF_INET6,
    48: socket.AF_UNIX,
}
PP_V2_PROTOCOLS = {
    0: "UNSPEC",
    socket.SOCK_STREAM: "TCP",
    socket.SOCK_DGRAM: "UDP",
}
PP_V2_ADDRESS_FORMATS = {
    17: "!4s4s2H",
    18: "!4s4s2H",
    33: "!16s16s2H",
    34: "!16s16s2H",
    49: "!108s108s",
    50: "!108s108s",
}

ProxyProtocolHeader = collections.namedtuple(
    "ProxyProtocolHeader",
    [
        "version",
        "command",
        "protocol",
        "address_family",
        "source_address",
        "source_port",
        "dest_address",
        "dest_port",
    ],
)


class ProxyProtocol(object):
    def __init__(self):
        self.pp = ProxyProtocolHeader
        self.header_length = 16
        self.logger = get_logger("paramiko.proxy_protocol")

    def parse(self, sock):
        """
        Reads the first 16 bytes from the socket to determine which
        version of the proxy protocol is used (if any)
        """
        header = sock.recv(self.header_length, socket.MSG_PEEK)
        if header.startswith(PP_V1_SIGNATURE):
            self.logger.log(DEBUG, "Signature v1 detected")
            return self._parse_pp_v1(sock)
        elif header.startswith(PP_V2_SIGNATURE):
            self.logger.log(DEBUG, "Signature v2 detected")
            return self._parse_pp_v2(sock, header)
        else:
            self.logger.log(DEBUG, "Signature not found")
            return None

    def _parse_pp_v1(self, sock):
        try:
            header = sock.recv(107, socket.MSG_PEEK)
        except Exception as e:
            raise ProxyProtocolException(
                "Failed to read proxy v1 header" + str(e)
            )

        # The CRLF sequence must be found in the first 107 characters
        if PP_V1_CRLF not in header:
            self.logger.log(DEBUG, "HEADER : {}".format(header))
            raise ProxyProtocolException("Failed to read CRLF sequence")

        # Get only what we need
        pp_size = header.find(PP_V1_CRLF) + len(PP_V1_CRLF)
        pp_line = sock.recv(pp_size)
        try:
            v1_sign, protocol, s_addr, d_addr, s_port, d_port = pp_line.split()
        except:
            raise ProxyProtocolException(
                "Failed to parse proxy v1 header line : {}".format(pp_line)
            )

        try:
            family = PP_V1_ADDRESS_FAMILIES[protocol]
        except:
            raise ProxyProtocolException("Failed to get proxy v1 protocol.")

        if family == socket.AF_UNSPEC:
            return None

        self.pp.version = 1
        self.pp.protocol = protocol
        self.pp.source_address = self._is_valid_ip_address(family, s_addr)
        self.pp.source_port = s_port
        self.pp.dest_address = self._is_valid_ip_address(family, d_addr)
        self.pp.dest_port = d_port

        return self.pp

    def _parse_pp_v2(self, sock, header):
        """
        Implements version 2 of the proxy protocol.
        The header parameter is passed to avoid another socket.recv() call
        to get the full header length.
        """
        pp_header_format = ">12sccH"
        pp_header = struct.unpack(pp_header_format, header)
        version_and_command = byte_ord(pp_header[1])
        family_and_proto = byte_ord(pp_header[2])
        address_length = pp_header[3]

        pp_line = sock.recv(self.header_length + address_length)
        version = version_and_command & 0xF0
        if version != PP_V2_VERSION:
            raise ProxyProtocolException(
                "Invalid proxy protocol v2 version : {}".format(version)
            )
        self.pp.version = 2

        try:
            self.pp.command = PP_V2_COMMANDS[version_and_command & 0x0F]
        except:
            raise ProxyProtocolException("Invalid proxy protocol v2 command")

        try:
            self.pp.protocol = PP_V2_PROTOCOLS[family_and_proto & 0x0F]
        except:
            raise ProxyProtocolException("Invalid proxy protocol v2 protocol")

        try:
            family = PP_V2_ADDRESS_FAMILIES[family_and_proto & 0xF0]
        except:
            raise ProxyProtocolException("Invalid proxy protocol v2 family")

        address_format = PP_V2_ADDRESS_FORMATS[family_and_proto]
        address_info = pp_line[16 : 16 + struct.calcsize(address_format)]
        try:
            s_addr, d_addr, s_port, d_port = struct.unpack(
                address_format, address_info
            )
        except:
            raise ProxyProtocolException(
                "Failed to parse proxy v2 header line : {}".format(pp_line)
            )

        self.pp.source_address = self._convert_address(family, s_addr)
        self.pp.source_port = s_port
        self.pp.dest_address = self._convert_address(family, d_addr)
        self.pp.dest_port = d_port

        return self.pp

    def _convert_address(self, family, addr):
        """
        Convert packed IPv4/IPv6 address bytes to an human readable
        ASCII version
        """
        if family is socket.AF_INET:
            addr = b".".join(
                ("%i" % (byte_ord(b),)).encode("ascii") for b in addr
            )
        elif family is socket.AF_INET6:
            hexaddr = binascii.b2a_hex(addr)
            addr = b":".join(
                ("%x" % (int(hexaddr[b : b + 4], 16),)).encode("ascii")
                for b in range(0, 32, 4)
            )
        elif family == socket.AF_UNIX:
            return addr.rstrip(b"\x00")
        else:
            raise ProxyProtocolException(
                "Unknown INET family : {}".format(family)
            )

        return self._is_valid_ip_address(family, addr)

    def _is_valid_ip_address(self, family, address):
        """
        Check if the provided IP address is valid
        """
        try:
            socket.inet_pton(family, b2s(address))
        except socket.error:
            raise ProxyProtocolException(
                "Invalid IP address : {}".format(address)
            )

        return address


class ProxyProtocolException(Exception):
    pass
