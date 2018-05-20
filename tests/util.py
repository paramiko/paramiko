from os.path import dirname, realpath, join

import pytest

from paramiko.py3compat import builtins


def _support(filename):
    return join(dirname(realpath(__file__)), filename)


# TODO: consider using pytest.importorskip('gssapi') instead? We presumably
# still need CLI configurability for the Kerberos parameters, though, so can't
# JUST key off presence of GSSAPI optional dependency...
# TODO: anyway, s/True/os.environ.get('RUN_GSSAPI', False)/ or something.
needs_gssapi = pytest.mark.skipif(True, reason="No GSSAPI to test")


def needs_builtin(name):
    """
    Skip decorated test if builtin name does not exist.
    """
    reason = "Test requires a builtin '{}'".format(name)
    return pytest.mark.skipif(not hasattr(builtins, name), reason=reason)


slow = pytest.mark.slow
