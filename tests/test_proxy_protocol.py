import unittest
import socket

from mock import Mock, patch
from paramiko.proxy_protocol import ProxyProtocol, ProxyProtocolException
from paramiko.common import DEBUG
from paramiko.py3compat import PY2

PP_V1_SIGN = b"PROXY"
PP_V1_CRLF = b"\r\n"
PP_V2_SIGN = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"


def make_tcp4_v1_header(
    sign=PP_V1_SIGN,
    proto=b"TCP4",
    src_addr=b"1.2.3.4",
    dst_addr=b"5.6.7.8",
    src_port=b"8080",
    dst_port=b"8888",
    crlf=PP_V1_CRLF,
):
    args = [sign, proto, src_addr, dst_addr, src_port, dst_port, crlf]
    return b" ".join(args)


def make_tcp6_v1_header(
    sign=PP_V1_SIGN,
    proto=b"TCP6",
    src_addr=b"::1",
    dst_addr=b"::1",
    src_port=b"8080",
    dst_port=b"8888",
    crlf=PP_V1_CRLF,
):
    args = [sign, proto, src_addr, dst_addr, src_port, dst_port, crlf]
    return b" ".join(args)


def make_tcp4_v2_header(
    sign=PP_V2_SIGN,
    version=b"\x21",
    proto=b"\x11",
    addr_len=b"\x00\x0C",
    addrs=b"\x01\x02\x03\x04\x05\x06\x07\x08",
    ports=b"\x1F\x90\x22\xB8",
):
    return sign + version + proto + addr_len + addrs + ports


def make_tcp6_v2_header(
    sign=PP_V2_SIGN,
    version=b"\x21",
    proto=b"\x21",
    addr_len=b"\x00\x24",
    addrs=((b"\x00" * 15) + b"\x01") * 2,
    ports=b"\x1F\x90\x22\xB8",
):
    return sign + version + proto + addr_len + addrs + ports


class ProxyProtocolTest(unittest.TestCase):
    def setUp(self):
        self.pp = ProxyProtocol()
        self.sock = Mock()
        if PY2:
            self.assertRaisesRegex = self.assertRaisesRegexp

    @patch("paramiko.proxy_protocol.ProxyProtocol._parse_pp_v1")
    @patch("paramiko.proxy_protocol.ProxyProtocol._parse_pp_v2")
    def test_signature(self, m_pp_v2, m_pp_v1):
        """
        verify that the correct parser is called.
        """
        self.sock.recv.return_value = b"NOPROXY "
        info = self.pp.parse(self.sock)
        m_pp_v1.assert_not_called()
        m_pp_v2.assert_not_called()
        self.assertEqual(None, info)
        m_pp_v1.reset_mock()
        m_pp_v2.reset_mock()

        self.sock.recv.return_value = PP_V1_SIGN
        self.pp.parse(self.sock)
        m_pp_v1.assert_called_once()
        m_pp_v2.assert_not_called()
        m_pp_v1.reset_mock()
        m_pp_v2.reset_mock()

        self.sock.recv.return_value = PP_V2_SIGN
        self.pp.parse(self.sock)
        m_pp_v1.assert_not_called()
        m_pp_v2.assert_called_once()
        m_pp_v1.reset_mock()
        m_pp_v2.reset_mock()

    def test_valid_ip_address(self):
        """
        Verify that valid IP addresses are properly decoded.
        """
        addr = self.pp._is_valid_ip_address(socket.AF_INET, "1.2.3.4")
        self.assertEqual("1.2.3.4", addr)

        addr = self.pp._is_valid_ip_address(socket.AF_INET6, "::1")
        self.assertEqual("::1", addr)

    def test_invalid_ip_address(self):
        """
        Verify that Exception is raised if an invalid IP address is decoded.
        """
        for ip in (" ", "::1", "3234.23.453.353", "-2.23.24.234", "1.2.3"):
            self.assertRaisesRegex(
                ProxyProtocolException,
                "Invalid IP address : {}".format(ip),
                self.pp._is_valid_ip_address,
                socket.AF_INET,
                ip,
            )

        for ip in (" ", "1:", "::::", "foo", "1.2.3"):
            self.assertRaisesRegex(
                ProxyProtocolException,
                "Invalid IP address : {}".format(ip),
                self.pp._is_valid_ip_address,
                socket.AF_INET6,
                ip,
            )


class ProxyProtocolV1Test(unittest.TestCase):
    def setUp(self):
        self.pp = ProxyProtocol()
        self.parse = self.pp._parse_pp_v1
        self.sock = Mock()
        if PY2:
            self.assertRaisesRegex = self.assertRaisesRegexp

    def test_no_crlf(self):
        """
        verify that an Exception is raised if no CRLF is found in the first
        107 characters.
        """
        self.sock.recv.return_value = make_tcp4_v1_header(crlf=b"")
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Failed to read CRLF sequence",
            self.parse,
            self.sock,
        )

    def test_no_protocol(self):
        """
        verify that an Exception is raised when protocol is undeclared.
        """
        self.sock.recv.return_value = make_tcp4_v1_header(proto=b"NOPROTO")
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Failed to get proxy v1 protocol",
            self.pp._parse_pp_v1,
            self.sock,
        )

    def test_unknown_protocol(self):
        """
        verify that parser returns None if UNKNOWN protocol is parsed.
        """
        self.sock.recv.return_value = make_tcp4_v1_header(proto=b"UNKNOWN")
        info = self.parse(self.sock)
        self.assertEqual(None, info)

    def test_bad_header_format(self):
        """
        verify that an Exception is raised if header cannot be parsed.
        """
        self.sock.recv.return_value = make_tcp4_v1_header(src_addr=b"")
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Failed to parse proxy v1 header line",
            self.parse,
            self.sock,
        )

    def test_tcp4(self):
        """
        verify that parsing info is correct if a TCP4 v1 header is passed.
        """
        header = make_tcp4_v1_header()
        self.pp.logger.log(DEBUG, "HEADER : {}".format(header))
        self.sock.recv.return_value = header
        info = self.parse(self.sock)
        self.assertEqual(b"TCP4", info.protocol)
        self.assertEqual(b"1.2.3.4", info.source_address)
        self.assertEqual(b"5.6.7.8", info.dest_address)
        self.assertEqual(b"8080", info.source_port)
        self.assertEqual(b"8888", info.dest_port)

    def test_tcp6(self):
        """
        verify that parsing info is correct if a TCP6 v1 header is passed.
        """
        self.sock.recv.return_value = make_tcp6_v1_header()
        info = self.parse(self.sock)
        self.assertEqual(b"TCP6", info.protocol)
        self.assertEqual(b"::1", info.source_address)
        self.assertEqual(b"::1", info.dest_address)
        self.assertEqual(b"8080", info.source_port)
        self.assertEqual(b"8888", info.dest_port)


class ProxyProtocolV2Test(unittest.TestCase):
    def setUp(self):
        self.pp = ProxyProtocol()
        self.parse = self.pp._parse_pp_v2
        self.sock = Mock()
        if PY2:
            self.assertRaisesRegex = self.assertRaisesRegexp

    def test_invalid_version(self):
        """
        verify that an Exception is raised if version is not 0x20
        """
        header = make_tcp4_v2_header(version=b"\x01")
        self.sock.recv.return_value = header
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Invalid proxy protocol v2 version",
            self.parse,
            self.sock,
            header[:16],
        )

    def test_invalid_command(self):
        """
        verify that an Exception is raised if command is unknown
        """
        header = make_tcp4_v2_header(version=b"\x22")
        self.sock.recv.return_value = header
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Invalid proxy protocol v2 command",
            self.parse,
            self.sock,
            header[:16],
        )

    def test_invalid_family(self):
        """
        verify that an Exception is raised if INET family is unknown
        """
        header = make_tcp4_v2_header(proto=b"\x51")
        self.sock.recv.return_value = header
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Invalid proxy protocol v2 family",
            self.parse,
            self.sock,
            header[:16],
        )

    def test_invalid_protocol(self):
        """
        verify that an Exception is raised if protocol is unknown
        """
        header = make_tcp4_v2_header(proto=b"\x15")
        self.sock.recv.return_value = header
        self.assertRaisesRegex(
            ProxyProtocolException,
            "Invalid proxy protocol v2 protocol",
            self.parse,
            self.sock,
            header[:16],
        )

    def test_tcp4(self):
        """
        verify that TCP4 v2 header is properly parsed.
        """
        header = make_tcp4_v2_header()
        self.sock.recv.return_value = header
        info = self.parse(self.sock, header[:16])
        self.assertEqual("TCP", info.protocol)
        self.assertEqual(b"1.2.3.4", info.source_address)
        self.assertEqual(b"5.6.7.8", info.dest_address)
        self.assertEqual(8080, info.source_port)
        self.assertEqual(8888, info.dest_port)

    def test_tcp6(self):
        """
        verify that TCP6 v2 header is properly parsed.
        """
        header = make_tcp6_v2_header()
        self.sock.recv.return_value = header
        info = self.parse(self.sock, header[:16])
        self.assertEqual("TCP", info.protocol)
        self.assertEqual(b"0:0:0:0:0:0:0:1", info.source_address)
        self.assertEqual(b"0:0:0:0:0:0:0:1", info.dest_address)
        self.assertEqual(8080, info.source_port)
        self.assertEqual(8888, info.dest_port)
