import pickle
import unittest

from paramiko.ssh_exception import NoValidConnectionsError


class NoValidConnectionsErrorTest (unittest.TestCase):

    def test_pickling(self):
        # Regression test for https://github.com/paramiko/paramiko/issues/617
        exc = NoValidConnectionsError({'ab': ''})
        new_exc = pickle.loads(pickle.dumps(exc))
        self.assertEqual(type(exc), type(new_exc))
        self.assertEqual(str(exc), str(new_exc))
        self.assertEqual(exc.args, new_exc.args)
