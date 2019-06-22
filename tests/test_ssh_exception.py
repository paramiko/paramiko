import pickle

import pytest

from paramiko import RSAKey
from paramiko.ssh_exception import (
    BadAuthenticationType,
    PartialAuthentication,
    ChannelException,
    BadHostKeyException,
    ProxyCommandFailure,
)


@pytest.mark.parametrize(['exc'], [
    (BadAuthenticationType("Bad authentication type", ["ok", "also-ok"]),),
    (PartialAuthentication(["ok", "also-ok"]),),
    (BadHostKeyException("myhost", RSAKey.generate(2048), RSAKey.generate(2048)),),
    (ProxyCommandFailure("nc servername 22", 1),),
    (ChannelException(17, "whatever"),),
])
def test_ssh_exception_strings(exc):
    assert isinstance(str(exc), str)
    assert isinstance(repr(exc), str)
    if type(exc) != BadHostKeyException:
        ne = pickle.loads(pickle.dumps(exc))
        assert type(ne) == type(exc)
