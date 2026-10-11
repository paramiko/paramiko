import builtins
import os
import socket
import struct
import threading
import time
from contextlib import contextmanager
from os.path import dirname, join, realpath
from pathlib import Path

import pytest

from paramiko import (
    AUTH_FAILED,
    AUTH_PARTIALLY_SUCCESSFUL,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
    Ed25519Key,
    InteractiveQuery,
    RSAKey,
    ServerInterface,
    Transport,
)

from ._loop import LoopSocket

tests_dir = dirname(realpath(__file__))


def _support(filename):
    base = Path(tests_dir)
    top = base / filename
    deeper = base / "_support" / filename
    return str(deeper if deeper.exists() else top)


def _config(name):
    return join(tests_dir, "configs", name)


def needs_builtin(name):
    """
    Skip decorated test if builtin name does not exist.
    """
    reason = "Test requires a builtin '{}'".format(name)
    return pytest.mark.skipif(not hasattr(builtins, name), reason=reason)


slow = pytest.mark.slow


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


# TODO: doublecheck where _disable_xxx helpers were in use; disabling sha1 no
# longer makes any sense, and presumably neither does en/dis abling sha2 but
# that's the question innit

unicodey = "\u2022"


class TestServer(ServerInterface):
    paranoid_did_password = False
    paranoid_did_public_key = False
    paranoid_key = Ed25519Key.from_private_key_file(_support("ed25519.key"))

    def __init__(self, allowed_keys=None):
        self.allowed_keys = allowed_keys if allowed_keys is not None else []

    def check_channel_request(self, kind, chanid):
        if kind == "bogus":
            return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        return OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        if command != b"yes":
            return False
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_global_request(self, kind, msg):
        self._global_request = kind
        # NOTE: for w/e reason, older impl of this returned False always, even
        # tho that's only supposed to occur if the request cannot be served.
        # For now, leaving that the default unless test supplies specific
        # 'acceptable' request kind
        return kind == "acceptable"

    def check_channel_x11_request(
        self,
        channel,
        single_connection,
        auth_protocol,
        auth_cookie,
        screen_number,
    ):
        self._x11_single_connection = single_connection
        self._x11_auth_protocol = auth_protocol
        self._x11_auth_cookie = auth_cookie
        self._x11_screen_number = screen_number
        return True

    def check_port_forward_request(self, addr, port):
        self._listen = socket.socket()
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(1)
        return self._listen.getsockname()[1]

    def cancel_port_forward_request(self, addr, port):
        self._listen.close()
        self._listen = None

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self._tcpip_dest = destination
        return OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        if username == "slowdive":
            return "publickey,password"
        if username == "paranoid":
            if (
                not self.paranoid_did_password
                and not self.paranoid_did_public_key
            ):
                return "publickey,password"
            elif self.paranoid_did_password:
                return "publickey"
            else:
                return "password"
        if username == "commie":
            return "keyboard-interactive"
        if username == "utf8":
            return "password"
        if username == "non-utf8":
            return "password"
        return "publickey"

    def check_auth_password(self, username, password):
        if (username == "slowdive") and (password == "pygmalion"):
            return AUTH_SUCCESSFUL
        if (username == "paranoid") and (password == "paranoid"):
            # 2-part auth (even openssh doesn't support this)
            self.paranoid_did_password = True
            if self.paranoid_did_public_key:
                return AUTH_SUCCESSFUL
            return AUTH_PARTIALLY_SUCCESSFUL
        if (username == "utf8") and (password == unicodey):
            return AUTH_SUCCESSFUL
        if (username == "non-utf8") and (password == "\xff"):
            return AUTH_SUCCESSFUL
        if username == "bad-server":
            raise Exception("Ack!")
        if username == "unresponsive-server":
            time.sleep(5)
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if (username == "paranoid") and (key == self.paranoid_key):
            # 2-part auth
            self.paranoid_did_public_key = True
            if self.paranoid_did_password:
                return AUTH_SUCCESSFUL
            return AUTH_PARTIALLY_SUCCESSFUL
        # TODO: make sure all tests incidentally using this to pass, _without
        # sending a username oops_, get updated somehow - probably via server()
        # default always injecting a username
        elif key in self.allowed_keys:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        if username == "commie":
            self.username = username
            return InteractiveQuery(
                "password", "Please enter a password.", ("Password", False)
            )
        return AUTH_FAILED

    def check_auth_interactive_response(self, responses):
        if self.username == "commie":
            if (len(responses) == 1) and (responses[0] == "cat"):
                return AUTH_SUCCESSFUL
        return AUTH_FAILED


@contextmanager
def server(
    hostkey=None,
    init=None,
    server_init=None,
    client_init=None,
    connect=None,
    pubkeys=None,
    catch_error=False,
    transport_factory=None,
    server_transport_factory=None,
    defer=False,
    skip_verify=False,
):
    """
    SSH server contextmanager for testing.

    Yields a tuple of ``(tc, ts)`` (client- and server-side `Transport`
    objects), or ``(tc, ts, err)`` when ``catch_error==True``.

    :param hostkey:
        Host key to use for the server; if None, loads
        ``rsa.key``.
    :param init:
        Default `Transport` constructor kwargs to use for both sides.
    :param server_init:
        Extends and/or overrides ``init`` for server transport only.
    :param client_init:
        Extends and/or overrides ``init`` for client transport only.
    :param connect:
        Kwargs to use for ``connect()`` on the client.
    :param pubkeys:
        List of public keys for auth.
    :param catch_error:
        Whether to capture connection errors & yield from contextmanager.
        Necessary for connection_time exception testing.
    :param transport_factory:
        Like the same-named param in SSHClient: which Transport class to use.
    :param server_transport_factory:
        Like ``transport_factory``, but only impacts the server transport.
    :param bool defer:
        Whether to defer authentication during connecting.

        This is really just shorthand for ``connect={}`` which would do roughly
        the same thing. Also: this implies skip_verify=True automatically!
    :param bool skip_verify:
        Whether NOT to do the default "make sure auth passed" check.
    """
    if init is None:
        init = {}
    if server_init is None:
        server_init = {}
    if client_init is None:
        client_init = {}
    if connect is None:
        # No auth at all please
        if defer:
            connect = dict()
        # Default username based auth
        else:
            connect = dict(username="slowdive", password="pygmalion")
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    if transport_factory is None:
        transport_factory = Transport
    if server_transport_factory is None:
        server_transport_factory = transport_factory
    tc = transport_factory(sockc, **dict(init, **client_init))
    ts = server_transport_factory(socks, **dict(init, **server_init))

    if hostkey is None:
        hostkey = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(hostkey)
    event = threading.Event()
    server = TestServer(allowed_keys=pubkeys)
    assert not event.is_set()
    assert not ts.is_active()
    assert tc.get_username() is None
    assert ts.get_username() is None
    assert not tc.is_authenticated()
    assert not ts.is_authenticated()

    err = None
    # Trap errors and yield instead of raising right away;  otherwise callers
    # cannot usefully deal with problems at connect time which stem from errors
    # in the server side.
    try:
        ts.start_server(event, server)
        tc.connect(**connect)

        event.wait(1.0)
        assert event.is_set()
        assert ts.is_active()
        assert tc.is_active()

    except Exception as e:
        if not catch_error:
            raise
        err = e

    yield (tc, ts, err) if catch_error else (tc, ts)

    if not (catch_error or skip_verify or defer):
        assert ts.is_authenticated()
        assert tc.is_authenticated()

    tc.close()
    ts.close()
    socks.close()
    sockc.close()


def wait_until(condition, *, timeout=2):
    """
    Wait until `condition()` no longer raises an `AssertionError` or until
    `timeout` seconds have passed, which causes a `TimeoutError` to be raised.
    """
    deadline = time.time() + timeout

    while True:
        try:
            condition()
        except AssertionError as e:
            if time.time() > deadline:
                timeout_message = f"Condition not reached after {timeout}s"
                raise TimeoutError(timeout_message) from e
        else:
            return
        time.sleep(0.01)
