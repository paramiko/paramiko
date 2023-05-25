"""
Tests focusing primarily on the authentication step.

Thus, they concern AuthHandler and AuthStrategy, with a side of Transport.
"""

from logging import Logger
from unittest.mock import Mock

from pytest import raises

from paramiko import (
    AgentKey,
    AuthenticationException,
    AuthFailure,
    AuthResult,
    AuthSource,
    AuthStrategy,
    BadAuthenticationType,
    DSSKey,
    InMemoryPrivateKey,
    NoneAuth,
    OnDiskPrivateKey,
    Password,
    PrivateKey,
    PKey,
    RSAKey,
    SSHException,
    ServiceRequestingTransport,
    SourceResult,
)

from ._util import (
    _disable_sha1_pubkey,
    _disable_sha2,
    _disable_sha2_pubkey,
    _support,
    requires_sha1_signing,
    server,
    unicodey,
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
        def key_type_algo_selection_is_cert_suffix_aware(self):
            # This key has a cert next to it, which should trigger cert-aware
            # loading within key classes.
            privkey = PKey.from_path(_support("rsa.key"))
            server_init = dict(_disable_sha2_pubkey, server_sig_algs=False)
            with self._server(
                pubkeys=[privkey],
                connect=dict(pkey=privkey),
                server_init=server_init,
                catch_error=True,
            ) as (tc, ts, err):
                assert not err
                # Auth did work
                assert tc.is_authenticated()
                # Selected expected cert type
                assert (
                    tc._agreed_pubkey_algorithm
                    == "ssh-rsa-cert-v01@openssh.com"
                )

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


class AuthSource_:
    class base_class:
        def init_requires_and_saves_username(self):
            with raises(TypeError):
                AuthSource()
            assert AuthSource(username="foo").username == "foo"

        def dunder_repr_delegates_to_helper(self):
            source = AuthSource("foo")
            source._repr = Mock(wraps=lambda: "whatever")
            repr(source)
            source._repr.assert_called_once_with()

        def repr_helper_prints_basic_kv_pairs(self):
            assert repr(AuthSource("foo")) == "AuthSource()"
            assert (
                AuthSource("foo")._repr(bar="open") == "AuthSource(bar='open')"
            )

        def authenticate_takes_transport_and_is_abstract(self):
            # TODO: this test kinda just goes away once we're typed?
            with raises(TypeError):
                AuthSource("foo").authenticate()
            with raises(NotImplementedError):
                AuthSource("foo").authenticate(None)

    class NoneAuth_:
        def authenticate_auths_none(self):
            trans = Mock()
            result = NoneAuth("foo").authenticate(trans)
            trans.auth_none.assert_called_once_with("foo")
            assert result is trans.auth_none.return_value

        def repr_shows_class(self):
            assert repr(NoneAuth("foo")) == "NoneAuth()"

    class Password_:
        def init_takes_and_stores_password_getter(self):
            with raises(TypeError):
                Password("foo")
            getter = Mock()
            pw = Password("foo", password_getter=getter)
            assert pw.password_getter is getter

        def repr_adds_username(self):
            pw = Password("foo", password_getter=Mock())
            assert repr(pw) == "Password(user='foo')"

        def authenticate_gets_and_supplies_password(self):
            getter = Mock(return_value="bar")
            trans = Mock()
            pw = Password("foo", password_getter=getter)
            result = pw.authenticate(trans)
            trans.auth_password.assert_called_once_with("foo", "bar")
            assert result is trans.auth_password.return_value

    class PrivateKey_:
        def authenticate_calls_publickey_with_pkey(self):
            source = PrivateKey(username="foo")
            source.pkey = Mock()  # set by subclasses
            trans = Mock()
            result = source.authenticate(trans)
            trans.auth_publickey.assert_called_once_with("foo", source.pkey)
            assert result is trans.auth_publickey.return_value

    class InMemoryPrivateKey_:
        def init_takes_pkey_object(self):
            with raises(TypeError):
                InMemoryPrivateKey("foo")
            pkey = Mock()
            source = InMemoryPrivateKey(username="foo", pkey=pkey)
            assert source.pkey is pkey

        def repr_shows_pkey_repr(self):
            pkey = PKey.from_path(_support("ed25519.key"))
            source = InMemoryPrivateKey("foo", pkey)
            assert (
                repr(source)
                == "InMemoryPrivateKey(pkey=PKey(alg=ED25519, bits=256, fp=SHA256:J6VESFdD3xSChn8y9PzWzeF+1tl892mOy2TqkMLO4ow))"  # noqa
            )

        def repr_appends_agent_flag_when_AgentKey(self):
            real_key = PKey.from_path(_support("ed25519.key"))
            pkey = AgentKey(agent=None, blob=bytes(real_key))
            source = InMemoryPrivateKey("foo", pkey)
            assert (
                repr(source)
                == "InMemoryPrivateKey(pkey=PKey(alg=ED25519, bits=256, fp=SHA256:J6VESFdD3xSChn8y9PzWzeF+1tl892mOy2TqkMLO4ow)) [agent]"  # noqa
            )

    class OnDiskPrivateKey_:
        def init_takes_source_path_and_pkey(self):
            with raises(TypeError):
                OnDiskPrivateKey("foo")
            with raises(TypeError):
                OnDiskPrivateKey("foo", "bar")
            with raises(TypeError):
                OnDiskPrivateKey("foo", "bar", "biz")
            source = OnDiskPrivateKey(
                username="foo",
                source="ssh-config",
                path="of-exile",
                pkey="notreally",
            )
            assert source.username == "foo"
            assert source.source == "ssh-config"
            assert source.path == "of-exile"
            assert source.pkey == "notreally"

        def init_requires_specific_value_for_source(self):
            with raises(
                ValueError,
                match=r"source argument must be one of: \('ssh-config', 'python-config', 'implicit-home'\)",  # noqa
            ):
                OnDiskPrivateKey("foo", source="what?", path="meh", pkey="no")

        def repr_reflects_source_path_and_pkey(self):
            source = OnDiskPrivateKey(
                username="foo",
                source="ssh-config",
                path="of-exile",
                pkey="notreally",
            )
            assert (
                repr(source)
                == "OnDiskPrivateKey(key='notreally', source='ssh-config', path='of-exile')"  # noqa
            )


class AuthResult_:
    def setup_method(self):
        self.strat = AuthStrategy(None)

    def acts_like_list_with_strategy_attribute(self):
        with raises(TypeError):
            AuthResult()
        # kwarg works by itself
        AuthResult(strategy=self.strat)
        # or can be given as posarg w/ regular list() args after
        result = AuthResult(self.strat, [1, 2, 3])
        assert result.strategy is self.strat
        assert result == [1, 2, 3]
        assert isinstance(result, list)

    def repr_is_list_repr_untouched(self):
        result = AuthResult(self.strat, [1, 2, 3])
        assert repr(result) == "[1, 2, 3]"

    class dunder_str:
        def is_multiline_display_of_sourceresult_tuples(self):
            result = AuthResult(self.strat)
            result.append(SourceResult("foo", "bar"))
            result.append(SourceResult("biz", "baz"))
            assert str(result) == "foo -> bar\nbiz -> baz"

        def shows_str_not_repr_of_auth_source_and_result(self):
            result = AuthResult(self.strat)
            result.append(
                SourceResult(NoneAuth("foo"), ["password", "pubkey"])
            )
            assert str(result) == "NoneAuth() -> ['password', 'pubkey']"

        def empty_list_result_values_show_success_string(self):
            result = AuthResult(self.strat)
            result.append(SourceResult(NoneAuth("foo"), []))
            assert str(result) == "NoneAuth() -> success"


class AuthFailure_:
    def is_an_AuthenticationException(self):
        assert isinstance(AuthFailure(None), AuthenticationException)

    def init_requires_result(self):
        with raises(TypeError):
            AuthFailure()
        result = AuthResult(None)
        fail = AuthFailure(result=result)
        assert fail.result is result

    def str_is_newline_plus_result_str(self):
        result = AuthResult(None)
        result.append(SourceResult(NoneAuth("foo"), Exception("onoz")))
        fail = AuthFailure(result)
        assert str(fail) == "\nNoneAuth() -> onoz"


class AuthStrategy_:
    def init_requires_ssh_config_param_and_sets_up_a_logger(self):
        with raises(TypeError):
            AuthStrategy()
        conf = object()
        strat = AuthStrategy(ssh_config=conf)
        assert strat.ssh_config is conf
        assert isinstance(strat.log, Logger)
        assert strat.log.name == "paramiko.auth_strategy"

    def get_sources_is_abstract(self):
        with raises(NotImplementedError):
            AuthStrategy(None).get_sources()

    class authenticate:
        def setup_method(self):
            self.strat = AuthStrategy(None)  # ssh_config not used directly
            self.source, self.transport = NoneAuth(None), Mock()
            self.source.authenticate = Mock()
            self.strat.get_sources = Mock(return_value=[self.source])

        def requires_and_uses_transport_with_methods_returning_result(self):
            with raises(TypeError):
                self.strat.authenticate()
            result = self.strat.authenticate(self.transport)
            self.strat.get_sources.assert_called_once_with()
            self.source.authenticate.assert_called_once_with(self.transport)
            assert isinstance(result, AuthResult)
            assert result.strategy is self.strat
            assert len(result) == 1
            source_res = result[0]
            assert isinstance(source_res, SourceResult)
            assert source_res.source is self.source
            assert source_res.result is self.source.authenticate.return_value

        def logs_sources_attempted(self):
            self.strat.log = Mock()
            self.strat.authenticate(self.transport)
            self.strat.log.debug.assert_called_once_with("Trying NoneAuth()")

        def raises_AuthFailure_if_no_successes(self):
            self.strat.log = Mock()
            oops = Exception("onoz")
            self.source.authenticate.side_effect = oops
            with raises(AuthFailure) as info:
                self.strat.authenticate(self.transport)
            result = info.value.result
            assert isinstance(result, AuthResult)
            assert len(result) == 1
            source_res = result[0]
            assert isinstance(source_res, SourceResult)
            assert source_res.source is self.source
            assert source_res.result is oops
            self.strat.log.info.assert_called_once_with(
                "Authentication via NoneAuth() failed with Exception"
            )

        def short_circuits_on_successful_auth(self):
            kaboom = Mock(authenticate=Mock(side_effect=Exception("onoz")))
            self.strat.get_sources.return_value = [self.source, kaboom]
            result = self.strat.authenticate(self.transport)
            # No exception, and it's just a regular ol Result
            assert isinstance(result, AuthResult)
            # And it did not capture any attempt to execute the 2nd source
            assert len(result) == 1
            assert result[0].source is self.source
