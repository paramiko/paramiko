# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Some unit tests for SSHClient.
"""

from __future__ import with_statement, print_function

import gc
import os
import platform
import socket
import threading
import time
import unittest
import warnings
import weakref
from tempfile import mkstemp

from pytest_relaxed import raises

import paramiko
from paramiko.pkey import PublicBlob
from paramiko.common import PY2
from paramiko.ssh_exception import SSHException, AuthenticationException

from .util import _support, slow


requires_gss_auth = unittest.skipUnless(
    paramiko.GSS_AUTH_AVAILABLE, "GSS auth not available"
)

FINGERPRINTS = {
    "ssh-dss": b"\x44\x78\xf0\xb9\xa2\x3c\xc5\x18\x20\x09\xff\x75\x5b\xc1\xd2\x6c",
    "ssh-rsa": b"\x60\x73\x38\x44\xcb\x51\x86\x65\x7f\xde\xda\xa2\x2b\x5a\x57\xd5",
    "ecdsa-sha2-nistp256": b"\x25\x19\xeb\x55\xe6\xa1\x47\xff\x4f\x38\xd2\x75\x6f\xa5\xd5\x60",
    "ssh-ed25519": b'\xb3\xd5"\xaa\xf9u^\xe8\xcd\x0e\xea\x02\xb9)\xa2\x80',
}


class NullServer(paramiko.ServerInterface):
    def __init__(self, *args, **kwargs):
        # Allow tests to enable/disable specific key types
        self.__allowed_keys = kwargs.pop("allowed_keys", [])
        # And allow them to set a (single...meh) expected public blob (cert)
        self.__expected_public_blob = kwargs.pop("public_blob", None)
        super(NullServer, self).__init__(*args, **kwargs)

    def get_allowed_auths(self, username):
        if username == "slowdive":
            return "publickey,password"
        return "publickey"

    def check_auth_password(self, username, password):
        if (username == "slowdive") and (password == "pygmalion"):
            return paramiko.AUTH_SUCCESSFUL
        if (username == "slowdive") and (password == "unresponsive-server"):
            time.sleep(5)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        try:
            expected = FINGERPRINTS[key.get_name()]
        except KeyError:
            return paramiko.AUTH_FAILED
        # Base check: allowed auth type & fingerprint matches
        happy = (
            key.get_name() in self.__allowed_keys
            and key.get_fingerprint() == expected
        )
        # Secondary check: if test wants assertions about cert data
        if (
            self.__expected_public_blob is not None
            and key.public_blob != self.__expected_public_blob
        ):
            happy = False
        return paramiko.AUTH_SUCCESSFUL if happy else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        if command != b"yes":
            return False
        return True

    def check_channel_env_request(self, channel, name, value):
        if name == "INVALID_ENV":
            return False

        if not hasattr(channel, "env"):
            setattr(channel, "env", {})

        channel.env[name] = value
        return True


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.sockl = socket.socket()
        self.sockl.bind(("localhost", 0))
        self.sockl.listen(1)
        self.addr, self.port = self.sockl.getsockname()
        self.connect_kwargs = dict(
            hostname=self.addr,
            port=self.port,
            username="slowdive",
            look_for_keys=False,
        )
        self.event = threading.Event()
        self.kill_event = threading.Event()

    def tearDown(self):
        # Shut down client Transport
        if hasattr(self, "tc"):
            self.tc.close()
        # Shut down shared socket
        if hasattr(self, "sockl"):
            # Signal to server thread that it should shut down early; it checks
            # this immediately after accept(). (In scenarios where connection
            # actually succeeded during the test, this becomes a no-op.)
            self.kill_event.set()
            # Forcibly connect to server sock in case the server thread is
            # hanging out in its accept() (e.g. if the client side of the test
            # fails before it even gets to connecting); there's no other good
            # way to force an accept() to exit.
            put_a_sock_in_it = socket.socket()
            put_a_sock_in_it.connect((self.addr, self.port))
            put_a_sock_in_it.close()
            # Then close "our" end of the socket (which _should_ cause the
            # accept() to bail out, but does not, for some reason. I blame
            # threading.)
            self.sockl.close()

    def _run(
        self, allowed_keys=None, delay=0, public_blob=None, kill_event=None
    ):
        if allowed_keys is None:
            allowed_keys = FINGERPRINTS.keys()
        self.socks, addr = self.sockl.accept()
        # If the kill event was set at this point, it indicates an early
        # shutdown, so bail out now and don't even try setting up a Transport
        # (which will just verbosely die.)
        if kill_event and kill_event.is_set():
            self.socks.close()
            return
        self.ts = paramiko.Transport(self.socks)
        keypath = _support("test_rsa.key")
        host_key = paramiko.RSAKey.from_private_key_file(keypath)
        self.ts.add_server_key(host_key)
        keypath = _support("test_ecdsa_256.key")
        host_key = paramiko.ECDSAKey.from_private_key_file(keypath)
        self.ts.add_server_key(host_key)
        server = NullServer(allowed_keys=allowed_keys, public_blob=public_blob)
        if delay:
            time.sleep(delay)
        self.ts.start_server(self.event, server)

    def _test_connection(self, **kwargs):
        """
        (Most) kwargs get passed directly into SSHClient.connect().

        The exception is ``allowed_keys`` which is stripped and handed to the
        ``NullServer`` used for testing.
        """
        run_kwargs = {"kill_event": self.kill_event}
        for key in ("allowed_keys", "public_blob"):
            run_kwargs[key] = kwargs.pop(key, None)
        # Server setup
        threading.Thread(target=self._run, kwargs=run_kwargs).start()
        host_key = paramiko.RSAKey.from_private_key_file(
            _support("test_rsa.key")
        )
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        # Client setup
        self.tc = paramiko.SSHClient()
        self.tc.get_host_keys().add(
            "[%s]:%d" % (self.addr, self.port), "ssh-rsa", public_host_key
        )

        # Actual connection
        self.tc.connect(**dict(self.connect_kwargs, **kwargs))

        # Authentication successful?
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual("slowdive", self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())
        self.assertEqual(False, self.tc.get_transport().gss_kex_used)

        # Command execution functions?
        stdin, stdout, stderr = self.tc.exec_command("yes")
        schan = self.ts.accept(1.0)

        schan.send("Hello there.\n")
        schan.send_stderr("This is on stderr.\n")
        schan.close()

        self.assertEqual("Hello there.\n", stdout.readline())
        self.assertEqual("", stdout.readline())
        self.assertEqual("This is on stderr.\n", stderr.readline())
        self.assertEqual("", stderr.readline())

        # Cleanup
        stdin.close()
        stdout.close()
        stderr.close()


class SSHClientTest(ClientTest):
    def test_1_client(self):
        """
        verify that the SSHClient stuff works too.
        """
        self._test_connection(password="pygmalion")

    def test_2_client_dsa(self):
        """
        verify that SSHClient works with a DSA key.
        """
        self._test_connection(key_filename=_support("test_dss.key"))

    def test_client_rsa(self):
        """
        verify that SSHClient works with an RSA key.
        """
        self._test_connection(key_filename=_support("test_rsa.key"))

    def test_2_5_client_ecdsa(self):
        """
        verify that SSHClient works with an ECDSA key.
        """
        self._test_connection(key_filename=_support("test_ecdsa_256.key"))

    def test_client_ed25519(self):
        self._test_connection(key_filename=_support("test_ed25519.key"))

    def test_3_multiple_key_files(self):
        """
        verify that SSHClient accepts and tries multiple key files.
        """
        # This is dumb :(
        types_ = {
            "rsa": "ssh-rsa",
            "dss": "ssh-dss",
            "ecdsa": "ecdsa-sha2-nistp256",
        }
        # Various combos of attempted & valid keys
        # TODO: try every possible combo using itertools functions
        for attempt, accept in (
            (["rsa", "dss"], ["dss"]),  # Original test #3
            (["dss", "rsa"], ["dss"]),  # Ordering matters sometimes, sadly
            (["dss", "rsa", "ecdsa_256"], ["dss"]),  # Try ECDSA but fail
            (["rsa", "ecdsa_256"], ["ecdsa"]),  # ECDSA success
        ):
            try:
                self._test_connection(
                    key_filename=[
                        _support("test_{}.key".format(x)) for x in attempt
                    ],
                    allowed_keys=[types_[x] for x in accept],
                )
            finally:
                # Clean up to avoid occasional gc-related deadlocks.
                # TODO: use nose test generators after nose port
                self.tearDown()
                self.setUp()

    def test_multiple_key_files_failure(self):
        """
        Expect failure when multiple keys in play and none are accepted
        """
        # Until #387 is fixed we have to catch a high-up exception since
        # various platforms trigger different errors here >_<
        self.assertRaises(
            SSHException,
            self._test_connection,
            key_filename=[_support("test_rsa.key")],
            allowed_keys=["ecdsa-sha2-nistp256"],
        )

    def test_certs_allowed_as_key_filename_values(self):
        # NOTE: giving cert path here, not key path. (Key path test is below.
        # They're similar except for which path is given; the expected auth and
        # server-side behavior is 100% identical.)
        # NOTE: only bothered whipping up one cert per overall class/family.
        for type_ in ("rsa", "dss", "ecdsa_256", "ed25519"):
            cert_name = "test_{}.key-cert.pub".format(type_)
            cert_path = _support(os.path.join("cert_support", cert_name))
            self._test_connection(
                key_filename=cert_path,
                public_blob=PublicBlob.from_file(cert_path),
            )

    def test_certs_implicitly_loaded_alongside_key_filename_keys(self):
        # NOTE: a regular test_connection() w/ test_rsa.key would incidentally
        # test this (because test_xxx.key-cert.pub exists) but incidental tests
        # stink, so NullServer and friends were updated to allow assertions
        # about the server-side key object's public blob. Thus, we can prove
        # that a specific cert was found, along with regular authorization
        # succeeding proving that the overall flow works.
        for type_ in ("rsa", "dss", "ecdsa_256", "ed25519"):
            key_name = "test_{}.key".format(type_)
            key_path = _support(os.path.join("cert_support", key_name))
            self._test_connection(
                key_filename=key_path,
                public_blob=PublicBlob.from_file(
                    "{}-cert.pub".format(key_path)
                ),
            )

    def test_default_key_locations_trigger_cert_loads_if_found(self):
        # TODO: what it says on the tin: ~/.ssh/id_rsa tries to load
        # ~/.ssh/id_rsa-cert.pub. Right now no other tests actually test that
        # code path (!) so we're punting too, sob.
        pass

    def test_4_auto_add_policy(self):
        """
        verify that SSHClient's AutoAddPolicy works.
        """
        threading.Thread(target=self._run).start()
        hostname = "[%s]:%d" % (self.addr, self.port)
        key_file = _support("test_ecdsa_256.key")
        public_host_key = paramiko.ECDSAKey.from_private_key_file(key_file)

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(password="pygmalion", **self.connect_kwargs)

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual("slowdive", self.ts.get_username())
        self.assertEqual(True, self.ts.is_authenticated())
        self.assertEqual(1, len(self.tc.get_host_keys()))
        new_host_key = list(self.tc.get_host_keys()[hostname].values())[0]
        self.assertEqual(public_host_key, new_host_key)

    def test_5_save_host_keys(self):
        """
        verify that SSHClient correctly saves a known_hosts file.
        """
        warnings.filterwarnings("ignore", "tempnam.*")

        host_key = paramiko.RSAKey.from_private_key_file(
            _support("test_rsa.key")
        )
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())
        fd, localname = mkstemp()
        os.close(fd)

        client = paramiko.SSHClient()
        self.assertEquals(0, len(client.get_host_keys()))

        host_id = "[%s]:%d" % (self.addr, self.port)

        client.get_host_keys().add(host_id, "ssh-rsa", public_host_key)
        self.assertEquals(1, len(client.get_host_keys()))
        self.assertEquals(
            public_host_key, client.get_host_keys()[host_id]["ssh-rsa"]
        )

        client.save_host_keys(localname)

        with open(localname) as fd:
            assert host_id in fd.read()

        os.unlink(localname)

    def test_6_cleanup(self):
        """
        verify that when an SSHClient is collected, its transport (and the
        transport's packetizer) is closed.
        """
        # Skipped on PyPy because it fails on travis for unknown reasons
        if platform.python_implementation() == "PyPy":
            return

        threading.Thread(target=self._run).start()

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(**dict(self.connect_kwargs, password="pygmalion"))

        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())

        p = weakref.ref(self.tc._transport.packetizer)
        self.assertTrue(p() is not None)
        self.tc.close()
        del self.tc

        # force a collection to see whether the SSHClient object is deallocated
        # 2 GCs are needed on PyPy, time is needed for Python 3
        time.sleep(0.3)
        gc.collect()
        gc.collect()

        self.assertTrue(p() is None)

    def test_client_can_be_used_as_context_manager(self):
        """
        verify that an SSHClient can be used a context manager
        """
        threading.Thread(target=self._run).start()

        with paramiko.SSHClient() as tc:
            self.tc = tc
            self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.assertEquals(0, len(self.tc.get_host_keys()))
            self.tc.connect(**dict(self.connect_kwargs, password="pygmalion"))

            self.event.wait(1.0)
            self.assertTrue(self.event.is_set())
            self.assertTrue(self.ts.is_active())

            self.assertTrue(self.tc._transport is not None)

        self.assertTrue(self.tc._transport is None)

    def test_7_banner_timeout(self):
        """
        verify that the SSHClient has a configurable banner timeout.
        """
        # Start the thread with a 1 second wait.
        threading.Thread(target=self._run, kwargs={"delay": 1}).start()
        host_key = paramiko.RSAKey.from_private_key_file(
            _support("test_rsa.key")
        )
        public_host_key = paramiko.RSAKey(data=host_key.asbytes())

        self.tc = paramiko.SSHClient()
        self.tc.get_host_keys().add(
            "[%s]:%d" % (self.addr, self.port), "ssh-rsa", public_host_key
        )
        # Connect with a half second banner timeout.
        kwargs = dict(self.connect_kwargs, banner_timeout=0.5)
        self.assertRaises(paramiko.SSHException, self.tc.connect, **kwargs)

    def test_8_auth_trickledown(self):
        """
        Failed key auth doesn't prevent subsequent pw auth from succeeding
        """
        # NOTE: re #387, re #394
        # If pkey module used within Client._auth isn't correctly handling auth
        # errors (e.g. if it allows things like ValueError to bubble up as per
        # midway through #394) client.connect() will fail (at key load step)
        # instead of succeeding (at password step)
        kwargs = dict(
            # Password-protected key whose passphrase is not 'pygmalion' (it's
            # 'television' as per tests/test_pkey.py). NOTE: must use
            # key_filename, loading the actual key here with PKey will except
            # immediately; we're testing the try/except crap within Client.
            key_filename=[_support("test_rsa_password.key")],
            # Actual password for default 'slowdive' user
            password="pygmalion",
        )
        self._test_connection(**kwargs)

    @slow
    def test_9_auth_timeout(self):
        """
        verify that the SSHClient has a configurable auth timeout
        """
        # Connect with a half second auth timeout
        self.assertRaises(
            AuthenticationException,
            self._test_connection,
            password="unresponsive-server",
            auth_timeout=0.5,
        )

    @requires_gss_auth
    def test_10_auth_trickledown_gsskex(self):
        """
        Failed gssapi-keyex auth doesn't prevent subsequent key auth from succeeding
        """
        kwargs = dict(gss_kex=True, key_filename=[_support("test_rsa.key")])
        self._test_connection(**kwargs)

    @requires_gss_auth
    def test_11_auth_trickledown_gssauth(self):
        """
        Failed gssapi-with-mic auth doesn't prevent subsequent key auth from succeeding
        """
        kwargs = dict(gss_auth=True, key_filename=[_support("test_rsa.key")])
        self._test_connection(**kwargs)

    def test_12_reject_policy(self):
        """
        verify that SSHClient's RejectPolicy works.
        """
        threading.Thread(target=self._run).start()

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.assertRaises(
            paramiko.SSHException,
            self.tc.connect,
            password="pygmalion",
            **self.connect_kwargs
        )

    @requires_gss_auth
    def test_13_reject_policy_gsskex(self):
        """
        verify that SSHClient's RejectPolicy works,
        even if gssapi-keyex was enabled but not used.
        """
        # Test for a bug present in paramiko versions released before 2017-08-01
        threading.Thread(target=self._run).start()

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.assertRaises(
            paramiko.SSHException,
            self.tc.connect,
            password="pygmalion",
            gss_kex=True,
            **self.connect_kwargs
        )

    def _client_host_key_bad(self, host_key):
        threading.Thread(target=self._run).start()
        hostname = "[%s]:%d" % (self.addr, self.port)

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.WarningPolicy())
        known_hosts = self.tc.get_host_keys()
        known_hosts.add(hostname, host_key.get_name(), host_key)

        self.assertRaises(
            paramiko.BadHostKeyException,
            self.tc.connect,
            password="pygmalion",
            **self.connect_kwargs
        )

    def _client_host_key_good(self, ktype, kfile):
        threading.Thread(target=self._run).start()
        hostname = "[%s]:%d" % (self.addr, self.port)

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.RejectPolicy())
        host_key = ktype.from_private_key_file(_support(kfile))
        known_hosts = self.tc.get_host_keys()
        known_hosts.add(hostname, host_key.get_name(), host_key)

        self.tc.connect(password="pygmalion", **self.connect_kwargs)
        self.event.wait(1.0)
        self.assertTrue(self.event.is_set())
        self.assertTrue(self.ts.is_active())
        self.assertEqual(True, self.ts.is_authenticated())

    def test_host_key_negotiation_1(self):
        host_key = paramiko.ECDSAKey.generate()
        self._client_host_key_bad(host_key)

    def test_host_key_negotiation_2(self):
        host_key = paramiko.RSAKey.generate(2048)
        self._client_host_key_bad(host_key)

    def test_host_key_negotiation_3(self):
        self._client_host_key_good(paramiko.ECDSAKey, "test_ecdsa_256.key")

    def test_host_key_negotiation_4(self):
        self._client_host_key_good(paramiko.RSAKey, "test_rsa.key")

    def _setup_for_env(self):
        threading.Thread(target=self._run).start()

        self.tc = paramiko.SSHClient()
        self.tc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.assertEqual(0, len(self.tc.get_host_keys()))
        self.tc.connect(
            self.addr, self.port, username="slowdive", password="pygmalion"
        )

        self.event.wait(1.0)
        self.assertTrue(self.event.isSet())
        self.assertTrue(self.ts.is_active())

    def test_update_environment(self):
        """
        Verify that environment variables can be set by the client.
        """
        self._setup_for_env()
        target_env = {b"A": b"B", b"C": b"d"}

        self.tc.exec_command("yes", environment=target_env)
        schan = self.ts.accept(1.0)
        self.assertEqual(target_env, getattr(schan, "env", {}))
        schan.close()

    @unittest.skip("Clients normally fail silently, thus so do we, for now")
    def test_env_update_failures(self):
        self._setup_for_env()
        with self.assertRaises(SSHException) as manager:
            # Verify that a rejection by the server can be detected
            self.tc.exec_command("yes", environment={b"INVALID_ENV": b""})
        self.assertTrue(
            "INVALID_ENV" in str(manager.exception),
            "Expected variable name in error message",
        )
        self.assertTrue(
            isinstance(manager.exception.args[1], SSHException),
            "Expected original SSHException in exception",
        )

    def test_missing_key_policy_accepts_classes_or_instances(self):
        """
        Client.missing_host_key_policy() can take classes or instances.
        """
        # AN ACTUAL UNIT TEST?! GOOD LORD
        # (But then we have to test a private API...meh.)
        client = paramiko.SSHClient()
        # Default
        assert isinstance(client._policy, paramiko.RejectPolicy)
        # Hand in an instance (classic behavior)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        assert isinstance(client._policy, paramiko.AutoAddPolicy)
        # Hand in just the class (new behavior)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        assert isinstance(client._policy, paramiko.AutoAddPolicy)


class PasswordPassphraseTests(ClientTest):
    # TODO: most of these could reasonably be set up to use mocks/assertions
    # (e.g. "gave passphrase -> expect PKey was given it as the passphrase")
    # instead of suffering a real connection cycle.
    # TODO: in that case, move the below to be part of an integration suite?

    def test_password_kwarg_works_for_password_auth(self):
        # Straightforward / duplicate of earlier basic password test.
        self._test_connection(password="pygmalion")

    # TODO: more granular exception pending #387; should be signaling "no auth
    # methods available" because no key and no password
    @raises(SSHException)
    def test_passphrase_kwarg_not_used_for_password_auth(self):
        # Using the "right" password in the "wrong" field shouldn't work.
        self._test_connection(passphrase="pygmalion")

    def test_passphrase_kwarg_used_for_key_passphrase(self):
        # Straightforward again, with new passphrase kwarg.
        self._test_connection(
            key_filename=_support("test_rsa_password.key"),
            passphrase="television",
        )

    def test_password_kwarg_used_for_passphrase_when_no_passphrase_kwarg_given(
        self
    ):  # noqa
        # Backwards compatibility: passphrase in the password field.
        self._test_connection(
            key_filename=_support("test_rsa_password.key"),
            password="television",
        )

    @raises(AuthenticationException)  # TODO: more granular
    def test_password_kwarg_not_used_for_passphrase_when_passphrase_kwarg_given(
        self
    ):  # noqa
        # Sanity: if we're given both fields, the password field is NOT used as
        # a passphrase.
        self._test_connection(
            key_filename=_support("test_rsa_password.key"),
            password="television",
            passphrase="wat? lol no",
        )
