import pickle
import unittest

from paramiko.ssh_exception import NoValidConnectionsError


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
