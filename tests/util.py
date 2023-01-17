from os.path import dirname, realpath, join
import builtins
import os
import struct
import sys
import unittest

import pytest

from paramiko.ssh_gss import GSS_AUTH_AVAILABLE

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

tests_dir = dirname(realpath(__file__))


def _support(filename):
    return join(tests_dir, filename)


def _config(name):
    return join(tests_dir, "configs", name)


needs_gssapi = pytest.mark.skipif(
    not GSS_AUTH_AVAILABLE, reason="No GSSAPI to test"
)


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

if (
    os.environ.get("K5TEST_USER_PRINC", None)
    and os.environ.get("K5TEST_HOSTNAME", None)
    and os.environ.get("KRB5_KTNAME", None)
):  # add other vars as needed

    # The environment provides the required information
    class DummyK5Realm:
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
        # Use a dummy, that skips all tests
        class KerberosTestCase(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise unittest.SkipTest(
                    "Missing extension package k5test. "
                    'Please run "pip install k5test" '
                    "to install it."
                )


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


def is_low_entropy():
    """
    Attempts to detect whether running interpreter is low-entropy.

    "low-entropy" is defined as being in 32-bit mode and with the hash seed set
    to zero.
    """
    is_32bit = struct.calcsize("P") == 32 / 8
    # I don't see a way to tell internally if the hash seed was set this
    # way, but env should be plenty sufficient, this is only for testing.
    return is_32bit and os.environ.get("PYTHONHASHSEED", None) == "0"


def sha1_signing_unsupported():
    """
    This is used to skip tests in environments where SHA-1 signing is
    not supported by the backend.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    message = b"Some dummy text"
    try:
        private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA1(),
        )
        return False
    except UnsupportedAlgorithm as e:
        return e._reason is _Reasons.UNSUPPORTED_HASH


requires_sha1_signing = unittest.skipIf(
    sha1_signing_unsupported(), "SHA-1 signing not supported"
)
