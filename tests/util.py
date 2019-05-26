from os.path import dirname, realpath, join
import os
import sys
import unittest

import pytest

from paramiko.py3compat import builtins
from paramiko.ssh_gss import GSS_AUTH_AVAILABLE


def _support(filename):
    return join(dirname(realpath(__file__)), filename)


def needs_builtin(name):
    """
    Skip decorated test if builtin name does not exist.
    """
    reason = "Test requires a builtin '{}'".format(name)
    return pytest.mark.skipif(not hasattr(builtins, name), reason=reason)


slow = pytest.mark.slow


# GSSAPI / Kerberos related tests need a working Kerberos environment.
# The class `KerberosTestCase` provides such an environment or skips all tests.
# There are 3 distinct cases:
#
# - A Kerberos environment has already been created and the environment
#   contains the required information.
#
# - We can use the package 'k5test' to setup an working kerberos environment on
#   the fly.
#
# - We skip all tests.
#
# ToDo: add a Windows specific implementation?

class SkipKerberosTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raise unittest.SkipTest("Missing gssapi or k5test")


if not GSS_AUTH_AVAILABLE:
    KerberosTestCase = SkipKerberosTestCase

elif (os.environ.get("K5TEST_USER_PRINC") and
      os.environ.get("K5TEST_HOSTNAME") and
      os.environ.get("KRB5_KTNAME")):  # add other vars as needed
    # The environment provides the required information

    class DummyK5Realm(object):
        def __init__(self):
            for k in os.environ:
                if not k.startswith("K5TEST_"):
                    continue
                setattr(self, k[7:].lower(), os.environ[k])
            self.env = {}

    class KerberosTestCase(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.realm = DummyK5Realm()

        @classmethod
        def tearDownClass(cls):
            del cls.realm
else:
    try:
        # Try to setup a kerberos environment
        from k5test import KerberosTestCase
    except Exception:
        KerberosTestCase = SkipKerberosTestCase


def update_env(testcase, mapping, env=os.environ):
    """Modify os.environ during a test case and restore during cleanup."""
    saved_env = env.copy()

    def replace(target, source):
        target.update(source)
        for k in list(target):
            if k not in source:
                target.pop(k, None)

    testcase.addCleanup(replace, env, saved_env)
    env.update(mapping)
    return testcase


def k5shell(args=None):
    """Create a shell with an kerberos environment

    This can be used to debug paramiko or to test the old GSSAPI.
    To test a different GSSAPI, simply activate a suitable venv
    within the shell.
    """
    import k5test
    import atexit
    import subprocess
    k5 = k5test.K5Realm()
    atexit.register(k5.stop)
    os.environ.update(k5.env)
    for n in ("realm", "user_princ", "hostname"):
        os.environ["K5TEST_" + n.upper()] = getattr(k5, n)

    if not args:
        args = sys.argv[1:]
    if not args:
        args = [os.environ.get("SHELL", "bash")]
    sys.exit(subprocess.call(args))
