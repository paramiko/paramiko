import pickle
import unittest

from paramiko import RSAKey
from paramiko.ssh_exception import (
    NoValidConnectionsError,
    BadAuthenticationType,
    PartialAuthentication,
    ChannelException,
    BadHostKeyException,
    ProxyCommandFailure,
)


class NoValidConnectionsErrorTest(unittest.TestCase):
    def test_pickling(self):
        # Regression test for https://github.com/paramiko/paramiko/issues/617
        exc = NoValidConnectionsError({("127.0.0.1", "22"): Exception()})
        new_exc = pickle.loads(pickle.dumps(exc))
        self.assertEqual(type(exc), type(new_exc))
        self.assertEqual(str(exc), str(new_exc))
        self.assertEqual(exc.args, new_exc.args)

    def test_error_message_for_single_host(self):
        exc = NoValidConnectionsError({("127.0.0.1", "22"): Exception()})
        assert "Unable to connect to port 22 on 127.0.0.1" in str(exc)

    def test_error_message_for_two_hosts(self):
        exc = NoValidConnectionsError(
            {("127.0.0.1", "22"): Exception(), ("::1", "22"): Exception()}
        )
        assert "Unable to connect to port 22 on 127.0.0.1 or ::1" in str(exc)

    def test_error_message_for_multiple_hosts(self):
        exc = NoValidConnectionsError(
            {
                ("127.0.0.1", "22"): Exception(),
                ("::1", "22"): Exception(),
                ("10.0.0.42", "22"): Exception(),
            }
        )
        exp = "Unable to connect to port 22 on 10.0.0.42, 127.0.0.1 or ::1"
        assert exp in str(exc)


class ExceptionStringDisplayTest(unittest.TestCase):
    def test_BadAuthenticationType(self):
        exc = BadAuthenticationType(
            "Bad authentication type", ["ok", "also-ok"]
        )
        expected = "Bad authentication type; allowed types: ['ok', 'also-ok']"
        assert str(exc) == expected

    def test_PartialAuthentication(self):
        exc = PartialAuthentication(["ok", "also-ok"])
        expected = "Partial authentication; allowed types: ['ok', 'also-ok']"
        assert str(exc) == expected

    def test_BadHostKeyException(self):
        got_key = RSAKey.generate(2048)
        wanted_key = RSAKey.generate(2048)
        exc = BadHostKeyException("myhost", got_key, wanted_key)
        expected = "Host key for server 'myhost' does not match: got '{}', expected '{}'"  # noqa
        assert str(exc) == expected.format(
            got_key.get_base64(), wanted_key.get_base64()
        )

    def test_ProxyCommandFailure(self):
        exc = ProxyCommandFailure("man squid", 7)
        expected = 'ProxyCommand("man squid") returned nonzero exit status: 7'
        assert str(exc) == expected

    def test_ChannelException(self):
        exc = ChannelException(17, "whatever")
        assert str(exc) == "ChannelException(17, 'whatever')"
