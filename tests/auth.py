"""
Tests focusing primarily on the authentication step.

Thus, they concern AuthHandler, with a side of Transport.
"""

from pytest import raises

from paramiko import (
    RSAKey,
    DSSKey,
    BadAuthenticationType,
    AuthenticationException,
    SSHException,
    ServiceRequestingTransport,
)

from ._util import (
    _support,
    server,
    unicodey,
    requires_sha1_signing,
    _disable_sha2,
    _disable_sha2_pubkey,
    _disable_sha1_pubkey,
)


class AuthHandler_:
    """
    Most of these tests are explicit about the auth method they call.

    This is because not too many other tests do so (they rely on the implicit
    auth trigger of various connect() kwargs).
    """

    def bad_auth_type(self):
        """
        verify that we get the right exception when an unsupported auth
        type is requested.
        """
        # Server won't allow password auth for this user, so should fail
        # and return just publickey allowed types
        with server(
            connect=dict(username="unknown", password="error"),
            catch_error=True,
        ) as (_, _, err):
            assert isinstance(err, BadAuthenticationType)
            assert err.allowed_types == ["publickey"]

    def bad_password(self):
        """
        verify that a bad password gets the right exception, and that a retry
        with the right password works.
        """
        # NOTE: Transport.connect doesn't do any auth upfront if no userauth
        # related kwargs given.
        with server(defer=True) as (tc, ts):
            # Auth once, badly
            with raises(AuthenticationException):
                tc.auth_password(username="slowdive", password="error")
            # And again, correctly
            tc.auth_password(username="slowdive", password="pygmalion")

    def multipart_auth(self):
        """
        verify that multipart auth works.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password(
                username="paranoid", password="paranoid"
            ) == ["publickey"]
            key = DSSKey.from_private_key_file(_support("dss.key"))
            assert tc.auth_publickey(username="paranoid", key=key) == []

    def interactive_auth(self):
        """
        verify keyboard-interactive auth works.
        """

        def handler(title, instructions, prompts):
            self.got_title = title
            self.got_instructions = instructions
            self.got_prompts = prompts
            return ["cat"]

        with server(defer=True) as (tc, ts):
            assert tc.auth_interactive("commie", handler) == []
            assert self.got_title == "password"
            assert self.got_prompts == [("Password", False)]

    def interactive_fallback(self):
        """
        verify that a password auth attempt will fallback to "interactive"
        if password auth isn't supported but interactive is.
        """
        with server(defer=True) as (tc, ts):
            # This username results in an allowed_auth of just kbd-int,
            # and has a configured interactive->response on the server.
            assert tc.auth_password("commie", "cat") == []

    def utf8(self):
        """
        verify that utf-8 encoding happens in authentication.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("utf8", unicodey) == []

    def non_utf8(self):
        """
        verify that non-utf-8 encoded passwords can be used for broken
        servers.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("non-utf8", "\xff") == []

    def auth_exception_when_disconnected(self):
        """
        verify that we catch a server disconnecting during auth, and report
        it as an auth failure.
        """
        with server(defer=True, skip_verify=True) as (tc, ts), raises(
            AuthenticationException
        ):
            tc.auth_password("bad-server", "hello")

    def non_responsive_triggers_auth_exception(self):
        """
        verify that authentication times out if server takes to long to
        respond (or never responds).
        """
        with server(defer=True, skip_verify=True) as (tc, ts), raises(
            AuthenticationException
        ) as info:
            tc.auth_timeout = 1  # 1 second, to speed up test
            tc.auth_password("unresponsive-server", "hello")
            assert "Authentication timeout" in str(info.value)


class AuthOnlyHandler_:
    def _server(self, *args, **kwargs):
        kwargs.setdefault("transport_factory", ServiceRequestingTransport)
        return server(*args, **kwargs)

    class fallback_pubkey_algorithm:
        @requires_sha1_signing
        def key_type_algo_selected_when_no_server_sig_algs(self):
            privkey = RSAKey.from_private_key_file(_support("rsa.key"))
            # Server pretending to be an apparently common setup:
            # - doesn't support (or have enabled) sha2
            # - also doesn't support (or have enabled) server-sig-algs/ext-info
            # This is the scenario in which Paramiko has to guess-the-algo, and
            # where servers that don't support sha2 or server-sig-algs can give
            # us trouble.
            server_init = dict(_disable_sha2_pubkey, server_sig_algs=False)
            with self._server(
                pubkeys=[privkey],
                connect=dict(pkey=privkey),
                server_init=server_init,
                catch_error=True,
            ) as (tc, ts, err):
                # Auth did work
                assert tc.is_authenticated()
                # Selected ssh-rsa, instead of first-in-the-list (rsa-sha2-512)
                assert tc._agreed_pubkey_algorithm == "ssh-rsa"

        @requires_sha1_signing
        def uses_first_preferred_algo_if_key_type_not_in_list(self):
            # This is functionally the same as legacy AuthHandler, just
            # arriving at the same place in a different manner.
            privkey = RSAKey.from_private_key_file(_support("rsa.key"))
            server_init = dict(_disable_sha2_pubkey, server_sig_algs=False)
            with self._server(
                pubkeys=[privkey],
                connect=dict(pkey=privkey),
                server_init=server_init,
                client_init=_disable_sha1_pubkey,  # no ssh-rsa
                catch_error=True,
            ) as (tc, ts, err):
                assert not tc.is_authenticated()
                assert isinstance(err, AuthenticationException)
                assert tc._agreed_pubkey_algorithm == "rsa-sha2-512"


class SHA2SignaturePubkeys:
    def pubkey_auth_honors_disabled_algorithms(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(
                disabled_algorithms=dict(
                    pubkeys=["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]
                )
            ),
            catch_error=True,
        ) as (_, _, err):
            assert isinstance(err, SSHException)
            assert "no RSA pubkey algorithms" in str(err)

    def client_sha2_disabled_server_sha1_disabled_no_match(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            client_init=_disable_sha2_pubkey,
            server_init=_disable_sha1_pubkey,
            catch_error=True,
        ) as (tc, ts, err):
            assert isinstance(err, AuthenticationException)

    def client_sha1_disabled_server_sha2_disabled_no_match(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            client_init=_disable_sha1_pubkey,
            server_init=_disable_sha2_pubkey,
            catch_error=True,
        ) as (tc, ts, err):
            assert isinstance(err, AuthenticationException)

    @requires_sha1_signing
    def ssh_rsa_still_used_when_sha2_disabled(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        # NOTE: this works because key obj comparison uses public bytes
        # TODO: would be nice for PKey to grow a legit "give me another obj of
        # same class but just the public bits" using asbytes()
        with server(
            pubkeys=[privkey], connect=dict(pkey=privkey), init=_disable_sha2
        ) as (tc, _):
            assert tc.is_authenticated()

    @requires_sha1_signing
    def first_client_preferred_algo_used_when_no_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        # Server pretending to be an apparently common setup:
        # - doesn't support (or have enabled) sha2
        # - also doesn't support (or have enabled) server-sig-algs/ext-info
        # This is the scenario in which Paramiko has to guess-the-algo, and
        # where servers that don't support sha2 or server-sig-algs give us
        # trouble.
        server_init = dict(_disable_sha2_pubkey, server_sig_algs=False)
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            server_init=server_init,
            catch_error=True,
        ) as (tc, ts, err):
            assert not tc.is_authenticated()
            assert isinstance(err, AuthenticationException)
            # Oh no! this isn't ssh-rsa, and our server doesn't support sha2!
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-512"

    def sha2_512(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            # TODO: why is this passing without a username?
            connect=dict(pkey=privkey),
            init=dict(
                disabled_algorithms=dict(pubkeys=["ssh-rsa", "rsa-sha2-256"])
            ),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-512"

    def sha2_256(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(
                disabled_algorithms=dict(pubkeys=["ssh-rsa", "rsa-sha2-512"])
            ),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"

    def sha2_256_when_client_only_enables_256(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            # Client-side only; server still accepts all 3.
            client_init=dict(
                disabled_algorithms=dict(pubkeys=["ssh-rsa", "rsa-sha2-512"])
            ),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"
