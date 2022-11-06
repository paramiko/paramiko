import socket
import struct

import mock
import pytest

from paramiko.py3compat import BytesIO
from paramiko.socks_proxy import IPv6EnabledTCPServer, SOCKSMessage, SOCKSProxy


AUTH_METHOD_REQUEST = b"\x05\x01\x00"
CMD_REQUEST_IPV4 = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f@"
CMD_REQUEST_DOMAIN = b"\x05\x01\x00\x03\x09\x6C\x6F\x63\x61\x6C\x68\x6F\x73\x74\x1f\x40"  # noqa
CMD_REQUEST_IPV6 = b"\x05\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f@"  # noqa

AUTH_METHOD_RESPONSE = b"\x05\x00"
CMD_RESPONSE_IPV4 = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f@"
CMD_RESPONSE_IPV6 = b"\x05\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f@"  # noqa

LOCALHOST_IPV4 = struct.unpack("!I", socket.inet_aton("127.0.0.1"))[0]
LOCALHOST_IPV6_HI, LOCALHOST_IPV6_LO = struct.unpack(
    "!QQ",
    socket.inet_pton(socket.AF_INET6, "::1")
)


class TestSOCKSMessage:
    def test_encode(self):
        # auth method selection request
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        assert msg.asbytes() == AUTH_METHOD_REQUEST

        # auth method selection response
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(0)
        assert msg.asbytes() == AUTH_METHOD_RESPONSE

        # SOCKS CONNECT request for IPv4 destination
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        msg.add_char(1)
        msg.add_int(LOCALHOST_IPV4)
        msg.add_short(8000)
        assert msg.asbytes() == CMD_REQUEST_IPV4

        # SOCKS response for IPv4 destination
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(0)
        msg.add_char(0)
        msg.add_char(1)
        msg.add_int(LOCALHOST_IPV4)
        msg.add_short(8000)
        assert msg.asbytes() == CMD_RESPONSE_IPV4

        # SOCKS CONNECT request for domain destination
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        msg.add_char(3)
        msg.add_string("localhost")
        msg.add_short(8000)
        assert msg.asbytes() == CMD_REQUEST_DOMAIN

        # SOCKS CONNECT request for IPv6 destination
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(1)
        msg.add_char(0)
        msg.add_char(4)
        msg.add_int64(LOCALHOST_IPV6_HI)
        msg.add_int64(LOCALHOST_IPV6_LO)
        msg.add_short(8000)
        assert msg.asbytes() == CMD_REQUEST_IPV6

        # SOCKS response for IPv6 destination
        msg = SOCKSMessage()
        msg.add_char(5)
        msg.add_char(0)
        msg.add_char(0)
        msg.add_char(4)
        msg.add_int64(LOCALHOST_IPV6_HI)
        msg.add_int64(LOCALHOST_IPV6_LO)
        msg.add_short(8000)
        assert msg.asbytes() == CMD_RESPONSE_IPV6

    def test_decode(self):
        # auth method selection request
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(AUTH_METHOD_REQUEST)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_bytes(1) == b""

        # auth method selection response
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(AUTH_METHOD_RESPONSE)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 0
        assert msg.get_bytes(1) == b""

        # SOCKS CONNECT request for IPv4 destination
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(CMD_REQUEST_IPV4)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_char() == 1
        assert msg.get_int() == LOCALHOST_IPV4
        assert msg.get_short() == 8000
        assert msg.get_bytes(1) == b""

        # SOCKS response for IPv4 destination
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(CMD_RESPONSE_IPV4)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 0
        assert msg.get_char() == 0
        assert msg.get_char() == 1
        assert msg.get_int() == LOCALHOST_IPV4
        assert msg.get_short() == 8000
        assert msg.get_bytes(1) == b""

        # SOCKS CONNECT request for domain destination
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(CMD_REQUEST_DOMAIN)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_char() == 3
        assert msg.get_string() == "localhost"
        assert msg.get_short() == 8000
        assert msg.get_bytes(1) == b""

        # SOCKS CONNECT request for IPv6 destination
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(CMD_REQUEST_IPV6)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 1
        assert msg.get_char() == 0
        assert msg.get_char() == 4
        assert msg.get_int64() == LOCALHOST_IPV6_HI
        assert msg.get_int64() == LOCALHOST_IPV6_LO
        assert msg.get_short() == 8000
        assert msg.get_bytes(1) == b""

        # SOCKS response for IPv6 destination
        socket_mock = mock.Mock()
        socket_mock.makefile.return_value = BytesIO(CMD_RESPONSE_IPV6)
        msg = SOCKSMessage(socket_mock)
        assert msg.get_char() == 5
        assert msg.get_char() == 0
        assert msg.get_char() == 0
        assert msg.get_char() == 4
        assert msg.get_int64() == LOCALHOST_IPV6_HI
        assert msg.get_int64() == LOCALHOST_IPV6_LO
        assert msg.get_short() == 8000
        assert msg.get_bytes(1) == b""


class TestIPv6EnabledTCPServer:
    @mock.patch("paramiko.socks_proxy.ThreadingTCPServer.__init__")
    def test_ipv4(self, tcp_server_mock):
        """
        Test server is initialized for correct AF when given an IPv4 address.
        """
        request_handler_mock = mock.Mock()
        server = IPv6EnabledTCPServer(
            ("127.0.0.1", 1234), request_handler_mock
        )
        assert server.address_family == socket.AF_INET
        tcp_server_mock.assert_called_once_with(
            ("127.0.0.1", 1234), request_handler_mock, True
        )

    @mock.patch("paramiko.socks_proxy.ThreadingTCPServer.__init__")
    def test_ipv6(self, tcp_server_mock):
        """
        Test server is initialized for correct AF when given an IPv6 address.
        """
        request_handler_mock = mock.Mock()
        server = IPv6EnabledTCPServer(
            ("::1", 1234), request_handler_mock
        )
        assert server.address_family == socket.AF_INET6
        tcp_server_mock.assert_called_once_with(
            ("::1", 1234, 0, 0), request_handler_mock, True
        )

    @mock.patch("paramiko.socks_proxy.ThreadingTCPServer.__init__")
    @mock.patch("paramiko.socks_proxy.families_and_addresses")
    def test_host(self, faa_mock, tcp_server_mock):
        """
        Test server is initialized for correct AF when given a host name.
        """
        faa_mock.return_value = iter([(
            socket.AF_INET, ("127.0.0.1", 1234)
        )])
        request_handler_mock = mock.Mock()
        server = IPv6EnabledTCPServer(
            ("dummy.ipv4.test", 1234), request_handler_mock
        )
        assert server.address_family == socket.AF_INET
        tcp_server_mock.assert_called_once_with(
            ("127.0.0.1", 1234), request_handler_mock, True
        )

        tcp_server_mock.reset_mock()

        faa_mock.return_value = iter([(
            socket.AF_INET6, ("::1", 1234)
        )])
        request_handler_mock = mock.Mock()
        server = IPv6EnabledTCPServer(
            ("dummy.ipv6.test", 1234), request_handler_mock
        )
        assert server.address_family == socket.AF_INET6
        tcp_server_mock.assert_called_once_with(
            ("::1", 1234), request_handler_mock, True
        )


class TestSOCKSProxy:
    @mock.patch("paramiko.socks_proxy.IPv6EnabledTCPServer")
    def test_socks_proxy(self, tcp_server_mock):
        """
        Test correct initialization of SOCKSProxy.
        """
        tcp_server_obj_mock = tcp_server_mock.return_value
        transport_mock = mock.Mock()

        socks_proxy = SOCKSProxy(transport_mock)

        assert socks_proxy.server == tcp_server_obj_mock
        assert socks_proxy.server.ssh_transport == transport_mock
        assert socks_proxy.get_address() == tcp_server_obj_mock.server_address

        socks_proxy.close()

        assert socks_proxy.server is None
        tcp_server_obj_mock.shutdown.assert_called_once_with()
        tcp_server_obj_mock.server_close.assert_called_once_with()

    @pytest.mark.parametrize("msg, resp", [
        pytest.param(
            b"\x08\x01\x00",
            b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00',
            id="invalid version"
        ),
        pytest.param(
            b"\x05\x01\x01",
            b"\x05\xff",
            id="missing support for no auth 1"
        ),
        pytest.param(
            b"\x05\x04\x01\x02\x03\x04",
            b"\x05\xff",
            id="missing support for no auth 2"
        )
    ])
    def test_invalid_auth_method_message(self, msg, resp):
        """
        Test that the SOCKS proxy returns proper responses for invalid
        auth method requests and closes the connection afterwards.
        """
        transport = mock.Mock()

        with SOCKSProxy(transport, bind_address="127.0.0.1", port=0) \
                as socks_proxy:
            listen_addr = socks_proxy.get_address()

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(listen_addr)
            s.sendall(msg)
            assert s.recv(32) == resp
            assert s.recv(32) == b""
            s.close()

        transport.open_channel.assert_not_called()

    @pytest.mark.parametrize("msg, resp", [
        pytest.param(
            b"\x08\x01\x00\x01\x7f\x00\x00\x01\x1f@",
            b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00',
            id="invalid version"
        ),
        pytest.param(
            b"\x05\x02\x00\x01\x7f\x00\x00\x01\x1f@",
            b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00',
            id="unsupported command 1"
        ),
        pytest.param(
            b"\x05\x03\x00\x01\x7f\x00\x00\x01\x1f@",
            b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00',
            id="unsupported command 2"
        ),
        pytest.param(
            b"\x05\x01\x01\x01\x7f\x00\x00\x01\x1f@",
            b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00',
            id="unsupported reserved byte"
        ),
        pytest.param(
            b"\x05\x01\x00\x02\x7f\x00\x00\x01\x1f@",
            b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00',
            id="unsupported address type 1"
        ),
        pytest.param(
            b"\x05\x01\x00\x05\x7f\x00\x00\x01\x1f@",
            b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00',
            id="unsupported address type 2"
        )
    ])
    def test_invalid_socks_message(self, msg, resp):
        """
        Test that the SOCKS proxy returns proper responses for invalid
        socks requests and closes the connection afterwards.
        """
        transport = mock.Mock()

        with SOCKSProxy(transport, bind_address="127.0.0.1", port=0) \
                as socks_proxy:
            listen_addr = socks_proxy.get_address()

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(listen_addr)
            s.sendall(AUTH_METHOD_REQUEST)
            assert s.recv(32) == AUTH_METHOD_RESPONSE
            s.sendall(msg)
            assert s.recv(32) == resp
            assert s.recv(32) == b""
            s.close()

        transport.open_channel.assert_not_called()

    def test_socks_conn_ipv4(self):
        """
        Test a successful SOCKS connection to an IPv4 enabled host.
        """
        channel = mock.Mock()
        transport = mock.Mock()
        transport.open_channel.return_value = channel

        with SOCKSProxy(transport, bind_address="127.0.0.1", port=0) \
                as socks_proxy:
            listen_addr = socks_proxy.get_address()

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(listen_addr)
            conn_addr = s.getsockname()
            s.send(AUTH_METHOD_REQUEST)
            assert s.recv(32) == AUTH_METHOD_RESPONSE
            s.send(CMD_REQUEST_IPV4)
            assert s.recv(32) == CMD_RESPONSE_IPV4
            s.close()

            transport.open_channel.assert_called_once_with(
                "direct-tcpip",
                dest_addr=("127.0.0.1", 8000),
                src_addr=conn_addr
            )

    def test_socks_conn_ipv6(self):
        """
        Test a successful SOCKS connection to an IPv6 enabled host.
        """
        channel = mock.Mock()
        transport = mock.Mock()
        transport.open_channel.return_value = channel

        with SOCKSProxy(transport, bind_address="::1", port=0) \
                as socks_proxy:
            listen_addr = socks_proxy.get_address()

            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.connect(listen_addr)
            conn_addr = s.getsockname()
            s.send(AUTH_METHOD_REQUEST)
            assert s.recv(32) == AUTH_METHOD_RESPONSE
            s.send(CMD_REQUEST_IPV6)
            assert s.recv(32) == CMD_RESPONSE_IPV6
            s.close()

            transport.open_channel.assert_called_once_with(
                "direct-tcpip",
                dest_addr=("::1", 8000),
                src_addr=conn_addr
            )
