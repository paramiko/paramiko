# This file is part of Paramiko and subject to the license in /LICENSE in this
# repository

from os.path import expanduser
from socket import gaierror

try:
    from invoke import Result
except ImportError:
    Result = None

from unittest.mock import patch
from pytest import raises, mark, fixture

from paramiko import (
    SSHConfig,
    SSHConfigDict,
    CouldNotCanonicalize,
    ConfigParseError,
)

from .util import _config


@fixture
def socket():
    """
    Patch all of socket.* in our config module to prevent eg real DNS lookups.

    Also forces getaddrinfo (used in our addressfamily lookup stuff) to always
    fail by default to mimic usual lack of AddressFamily related crap.

    Callers who want to mock DNS lookups can then safely assume gethostbyname()
    will be in use.
    """
    with patch("paramiko.config.socket") as mocket:
        # Reinstate gaierror as an actual exception and not a sub-mock.
        # (Presumably this would work with any exception, but why not use the
        # real one?)
        mocket.gaierror = gaierror
        # Patch out getaddrinfo, used to detect family-specific IP lookup -
        # only useful for a few specific tests.
        mocket.getaddrinfo.side_effect = mocket.gaierror
        # Patch out getfqdn to return some real string for when it gets called;
        # some code (eg tokenization) gets mad w/ MagicMocks
        mocket.getfqdn.return_value = "some.fake.fqdn"
        mocket.gethostname.return_value = "local.fake.fqdn"
        yield mocket


def load_config(name):
    return SSHConfig.from_path(_config(name))


class TestSSHConfig:
    def setup(self):
        self.config = load_config("robey")

    def test_init(self):
        # No args!
        with raises(TypeError):
            SSHConfig("uh oh!")
        # No args.
        assert not SSHConfig()._config

    def test_from_text(self):
        config = SSHConfig.from_text("User foo")
        assert config.lookup("foo.example.com")["user"] == "foo"

    def test_from_file(self):
        with open(_config("robey")) as flo:
            config = SSHConfig.from_file(flo)
        assert config.lookup("whatever")["user"] == "robey"

    def test_from_path(self):
        # NOTE: DO NOT replace with use of load_config() :D
        config = SSHConfig.from_path(_config("robey"))
        assert config.lookup("meh.example.com")["port"] == "3333"

    def test_parse_config(self):
        expected = [
            {"host": ["*"], "config": {}},
            {
                "host": ["*"],
                "config": {"identityfile": ["~/.ssh/id_rsa"], "user": "robey"},
            },
            {
                "host": ["*.example.com"],
                "config": {"user": "bjork", "port": "3333"},
            },
            {"host": ["*"], "config": {"crazy": "something dumb"}},
            {
                "host": ["spoo.example.com"],
                "config": {"crazy": "something else"},
            },
        ]
        assert self.config._config == expected

    @mark.parametrize(
        "host,values",
        (
            (
                "irc.danger.com",
                {
                    "crazy": "something dumb",
                    "hostname": "irc.danger.com",
                    "user": "robey",
                },
            ),
            (
                "irc.example.com",
                {
                    "crazy": "something dumb",
                    "hostname": "irc.example.com",
                    "user": "robey",
                    "port": "3333",
                },
            ),
            (
                "spoo.example.com",
                {
                    "crazy": "something dumb",
                    "hostname": "spoo.example.com",
                    "user": "robey",
                    "port": "3333",
                },
            ),
        ),
    )
    def test_host_config(self, host, values):
        expected = dict(
            values, hostname=host, identityfile=[expanduser("~/.ssh/id_rsa")]
        )
        assert self.config.lookup(host) == expected

    def test_fabric_issue_33(self):
        config = SSHConfig.from_text(
            """
Host www13.*
    Port 22

Host *.example.com
    Port 2222

Host *
    Port 3333
"""
        )
        host = "www13.example.com"
        expected = {"hostname": host, "port": "22"}
        assert config.lookup(host) == expected

    def test_proxycommand_config_equals_parsing(self):
        """
        ProxyCommand should not split on equals signs within the value.
        """
        config = SSHConfig.from_text(
            """
Host space-delimited
    ProxyCommand foo bar=biz baz

Host equals-delimited
    ProxyCommand=foo bar=biz baz
"""
        )
        for host in ("space-delimited", "equals-delimited"):
            value = config.lookup(host)["proxycommand"]
            assert value == "foo bar=biz baz"

    def test_proxycommand_interpolation(self):
        """
        ProxyCommand should perform interpolation on the value
        """
        config = SSHConfig.from_text(
            """
Host specific
    Port 37
    ProxyCommand host %h port %p lol

Host portonly
    Port 155

Host *
    Port 25
    ProxyCommand host %h port %p
"""
        )
        for host, val in (
            ("foo.com", "host foo.com port 25"),
            ("specific", "host specific port 37 lol"),
            ("portonly", "host portonly port 155"),
        ):
            assert config.lookup(host)["proxycommand"] == val

    def test_proxycommand_tilde_expansion(self):
        """
        Tilde (~) should be expanded inside ProxyCommand
        """
        config = SSHConfig.from_text(
            """
Host test
    ProxyCommand    ssh -F ~/.ssh/test_config bastion nc %h %p
"""
        )
        expected = "ssh -F {}/.ssh/test_config bastion nc test 22".format(
            expanduser("~")
        )
        got = config.lookup("test")["proxycommand"]
        assert got == expected

    @patch("paramiko.config.getpass")
    def test_proxyjump_token_expansion(self, getpass):
        getpass.getuser.return_value = "gandalf"
        config = SSHConfig.from_text(
            """
Host justhost
    ProxyJump jumpuser@%h
Host userhost
    ProxyJump %r@%h:222
Host allcustom
    ProxyJump %r@%h:%p
"""
        )
        assert config.lookup("justhost")["proxyjump"] == "jumpuser@justhost"
        assert config.lookup("userhost")["proxyjump"] == "gandalf@userhost:222"
        assert (
            config.lookup("allcustom")["proxyjump"] == "gandalf@allcustom:22"
        )

    @patch("paramiko.config.getpass")
    def test_controlpath_token_expansion(self, getpass, socket):
        getpass.getuser.return_value = "gandalf"
        config = SSHConfig.from_text(
            """
Host explicit_user
    User root
    ControlPath user %u remoteuser %r

Host explicit_host
    HostName ohai
    ControlPath remoteuser %r host %h orighost %n

Host hashbrowns
    ControlPath %C
        """
        )
        result = config.lookup("explicit_user")["controlpath"]
        # Remote user is User val, local user is User val
        assert result == "user gandalf remoteuser root"
        result = config.lookup("explicit_host")["controlpath"]
        # Remote user falls back to local user; host and orighost may differ
        assert result == "remoteuser gandalf host ohai orighost explicit_host"
        # Supports %C
        result = config.lookup("hashbrowns")["controlpath"]
        assert result == "a438e7dbf5308b923aba9db8fe2ca63447ac8688"

    def test_negation(self):
        config = SSHConfig.from_text(
            """
Host www13.* !*.example.com
    Port 22

Host *.example.com !www13.*
    Port 2222

Host www13.*
    Port 8080

Host *
    Port 3333
"""
        )
        host = "www13.example.com"
        expected = {"hostname": host, "port": "8080"}
        assert config.lookup(host) == expected

    def test_proxycommand(self):
        config = SSHConfig.from_text(
            """
Host proxy-with-equal-divisor-and-space
ProxyCommand = foo=bar

Host proxy-with-equal-divisor-and-no-space
ProxyCommand=foo=bar

Host proxy-without-equal-divisor
ProxyCommand foo=bar:%h-%p
"""
        )
        for host, values in {
            "proxy-with-equal-divisor-and-space": {
                "hostname": "proxy-with-equal-divisor-and-space",
                "proxycommand": "foo=bar",
            },
            "proxy-with-equal-divisor-and-no-space": {
                "hostname": "proxy-with-equal-divisor-and-no-space",
                "proxycommand": "foo=bar",
            },
            "proxy-without-equal-divisor": {
                "hostname": "proxy-without-equal-divisor",
                "proxycommand": "foo=bar:proxy-without-equal-divisor-22",
            },
        }.items():

            assert config.lookup(host) == values

    @patch("paramiko.config.getpass")
    def test_identityfile(self, getpass, socket):
        getpass.getuser.return_value = "gandalf"
        config = SSHConfig.from_text(
            """
IdentityFile id_dsa0

Host *
IdentityFile id_dsa1

Host dsa2
IdentityFile id_dsa2

Host dsa2*
IdentityFile id_dsa22

Host hashbrowns
IdentityFile %C
"""
        )
        for host, values in {
            "foo": {"hostname": "foo", "identityfile": ["id_dsa0", "id_dsa1"]},
            "dsa2": {
                "hostname": "dsa2",
                "identityfile": ["id_dsa0", "id_dsa1", "id_dsa2", "id_dsa22"],
            },
            "dsa22": {
                "hostname": "dsa22",
                "identityfile": ["id_dsa0", "id_dsa1", "id_dsa22"],
            },
            "hashbrowns": {
                "hostname": "hashbrowns",
                "identityfile": [
                    "id_dsa0",
                    "id_dsa1",
                    "a438e7dbf5308b923aba9db8fe2ca63447ac8688",
                ],
            },
        }.items():
            assert config.lookup(host) == values

    def test_config_addressfamily_and_lazy_fqdn(self):
        """
        Ensure the code path honoring non-'all' AddressFamily doesn't asplode
        """
        config = SSHConfig.from_text(
            """
AddressFamily inet
IdentityFile something_%l_using_fqdn
"""
        )
        assert config.lookup(
            "meh"
        )  # will die during lookup() if bug regresses

    def test_config_dos_crlf_succeeds(self):
        config = SSHConfig.from_text(
            """
Host abcqwerty\r\nHostName 127.0.0.1\r\n
"""
        )
        assert config.lookup("abcqwerty")["hostname"] == "127.0.0.1"

    def test_get_hostnames(self):
        expected = {"*", "*.example.com", "spoo.example.com"}
        assert self.config.get_hostnames() == expected

    def test_quoted_host_names(self):
        config = SSHConfig.from_text(
            """
Host "param pam" param "pam"
    Port 1111

Host "param2"
    Port 2222

Host param3 parara
    Port 3333

Host param4 "p a r" "p" "par" para
    Port 4444
"""
        )
        res = {
            "param pam": {"hostname": "param pam", "port": "1111"},
            "param": {"hostname": "param", "port": "1111"},
            "pam": {"hostname": "pam", "port": "1111"},
            "param2": {"hostname": "param2", "port": "2222"},
            "param3": {"hostname": "param3", "port": "3333"},
            "parara": {"hostname": "parara", "port": "3333"},
            "param4": {"hostname": "param4", "port": "4444"},
            "p a r": {"hostname": "p a r", "port": "4444"},
            "p": {"hostname": "p", "port": "4444"},
            "par": {"hostname": "par", "port": "4444"},
            "para": {"hostname": "para", "port": "4444"},
        }
        for host, values in res.items():
            assert config.lookup(host) == values

    def test_quoted_params_in_config(self):
        config = SSHConfig.from_text(
            """
Host "param pam" param "pam"
    IdentityFile id_rsa

Host "param2"
    IdentityFile "test rsa key"

Host param3 parara
    IdentityFile id_rsa
    IdentityFile "test rsa key"
"""
        )
        res = {
            "param pam": {"hostname": "param pam", "identityfile": ["id_rsa"]},
            "param": {"hostname": "param", "identityfile": ["id_rsa"]},
            "pam": {"hostname": "pam", "identityfile": ["id_rsa"]},
            "param2": {"hostname": "param2", "identityfile": ["test rsa key"]},
            "param3": {
                "hostname": "param3",
                "identityfile": ["id_rsa", "test rsa key"],
            },
            "parara": {
                "hostname": "parara",
                "identityfile": ["id_rsa", "test rsa key"],
            },
        }
        for host, values in res.items():
            assert config.lookup(host) == values

    def test_quoted_host_in_config(self):
        conf = SSHConfig()
        correct_data = {
            "param": ["param"],
            '"param"': ["param"],
            "param pam": ["param", "pam"],
            '"param" "pam"': ["param", "pam"],
            '"param" pam': ["param", "pam"],
            'param "pam"': ["param", "pam"],
            'param "pam" p': ["param", "pam", "p"],
            '"param" pam "p"': ["param", "pam", "p"],
            '"pa ram"': ["pa ram"],
            '"pa ram" pam': ["pa ram", "pam"],
            'param "p a m"': ["param", "p a m"],
        }
        incorrect_data = ['param"', '"param', 'param "pam', 'param "pam" "p a']
        for host, values in correct_data.items():
            assert conf._get_hosts(host) == values
        for host in incorrect_data:
            with raises(ConfigParseError):
                conf._get_hosts(host)

    def test_invalid_line_format_excepts(self):
        with raises(ConfigParseError):
            load_config("invalid")

    def test_proxycommand_none_issue_415(self):
        config = SSHConfig.from_text(
            """
Host proxycommand-standard-none
    ProxyCommand None

Host proxycommand-with-equals-none
    ProxyCommand=None
"""
        )
        for host, values in {
            "proxycommand-standard-none": {
                "hostname": "proxycommand-standard-none",
                "proxycommand": None,
            },
            "proxycommand-with-equals-none": {
                "hostname": "proxycommand-with-equals-none",
                "proxycommand": None,
            },
        }.items():

            assert config.lookup(host) == values

    def test_proxycommand_none_masking(self):
        # Re: https://github.com/paramiko/paramiko/issues/670
        config = SSHConfig.from_text(
            """
Host specific-host
    ProxyCommand none

Host other-host
    ProxyCommand other-proxy

Host *
    ProxyCommand default-proxy
"""
        )
        # In versions <3.0, 'None' ProxyCommands got deleted, and this itself
        # caused bugs. In 3.0, we more cleanly map "none" to None. This test
        # has been altered accordingly but left around to ensure no
        # regressions.
        assert config.lookup("specific-host")["proxycommand"] is None
        assert config.lookup("other-host")["proxycommand"] == "other-proxy"
        cmd = config.lookup("some-random-host")["proxycommand"]
        assert cmd == "default-proxy"

    def test_hostname_tokenization(self):
        result = load_config("hostname-tokenized").lookup("whatever")
        assert result["hostname"] == "prefix.whatever"


class TestSSHConfigDict:
    def test_SSHConfigDict_construct_empty(self):
        assert not SSHConfigDict()

    def test_SSHConfigDict_construct_from_list(self):
        assert SSHConfigDict([(1, 2)])[1] == 2

    def test_SSHConfigDict_construct_from_dict(self):
        assert SSHConfigDict({1: 2})[1] == 2

    @mark.parametrize("true_ish", ("yes", "YES", "Yes", True))
    def test_SSHConfigDict_as_bool_true_ish(self, true_ish):
        assert SSHConfigDict({"key": true_ish}).as_bool("key") is True

    @mark.parametrize("false_ish", ("no", "NO", "No", False))
    def test_SSHConfigDict_as_bool(self, false_ish):
        assert SSHConfigDict({"key": false_ish}).as_bool("key") is False

    @mark.parametrize("int_val", ("42", 42))
    def test_SSHConfigDict_as_int(self, int_val):
        assert SSHConfigDict({"key": int_val}).as_int("key") == 42

    @mark.parametrize("non_int", ("not an int", None, object()))
    def test_SSHConfigDict_as_int_failures(self, non_int):
        conf = SSHConfigDict({"key": non_int})

        try:
            int(non_int)
        except Exception as e:
            exception_type = type(e)

        with raises(exception_type):
            conf.as_int("key")

    def test_SSHConfig_host_dicts_are_SSHConfigDict_instances(self):
        config = SSHConfig.from_text(
            """
Host *.example.com
    Port 2222

Host *
    Port 3333
"""
        )
        assert config.lookup("foo.example.com").as_int("port") == 2222

    def test_SSHConfig_wildcard_host_dicts_are_SSHConfigDict_instances(self):
        config = SSHConfig.from_text(
            """
Host *.example.com
    Port 2222

Host *
    Port 3333
"""
        )
        assert config.lookup("anything-else").as_int("port") == 3333


class TestHostnameCanonicalization:
    # NOTE: this class uses on-disk configs, and ones with real (at time of
    # writing) DNS names, so that one can easily test OpenSSH's behavior using
    # "ssh -F path/to/file.config -G <target>".

    def test_off_by_default(self, socket):
        result = load_config("basic").lookup("www")
        assert result["hostname"] == "www"
        assert "user" not in result
        assert not socket.gethostbyname.called

    def test_explicit_no_same_as_default(self, socket):
        result = load_config("no-canon").lookup("www")
        assert result["hostname"] == "www"
        assert "user" not in result
        assert not socket.gethostbyname.called

    @mark.parametrize(
        "config_name",
        ("canon", "canon-always", "canon-local", "canon-local-always"),
    )
    def test_canonicalization_base_cases(self, socket, config_name):
        result = load_config(config_name).lookup("www")
        assert result["hostname"] == "www.paramiko.org"
        assert result["user"] == "rando"
        socket.gethostbyname.assert_called_once_with("www.paramiko.org")

    def test_uses_getaddrinfo_when_AddressFamily_given(self, socket):
        # Undo default 'always fails' mock
        socket.getaddrinfo.side_effect = None
        socket.getaddrinfo.return_value = [True]  # just need 1st value truthy
        result = load_config("canon-ipv4").lookup("www")
        assert result["hostname"] == "www.paramiko.org"
        assert result["user"] == "rando"
        assert not socket.gethostbyname.called
        gai_args = socket.getaddrinfo.call_args[0]
        assert gai_args[0] == "www.paramiko.org"
        assert gai_args[2] is socket.AF_INET  # Mocked, but, still useful

    @mark.skip
    def test_empty_CanonicalDomains_canonicalizes_despite_noop(self, socket):
        # Confirmed this is how OpenSSH behaves as well. Bit silly, but.
        # TODO: this requires modifying SETTINGS_REGEX, which is a mite scary
        # (honestly I'd prefer to move to a real parser lib anyhow) and since
        # this is a very dumb corner case, it's marked skip for now.
        result = load_config("empty-canon").lookup("www")
        assert result["hostname"] == "www"  # no paramiko.org
        assert "user" not in result  # did not discover canonicalized block

    def test_CanonicalDomains_may_be_set_to_space_separated_list(self, socket):
        # Test config has a bogus domain, followed by paramiko.org
        socket.gethostbyname.side_effect = [socket.gaierror, True]
        result = load_config("multi-canon-domains").lookup("www")
        assert result["hostname"] == "www.paramiko.org"
        assert result["user"] == "rando"
        assert [x[0][0] for x in socket.gethostbyname.call_args_list] == [
            "www.not-a-real-tld",
            "www.paramiko.org",
        ]

    def test_canonicalization_applies_to_single_dot_by_default(self, socket):
        result = load_config("deep-canon").lookup("sub.www")
        assert result["hostname"] == "sub.www.paramiko.org"
        assert result["user"] == "deep"

    def test_canonicalization_not_applied_to_two_dots_by_default(self, socket):
        result = load_config("deep-canon").lookup("subber.sub.www")
        assert result["hostname"] == "subber.sub.www"
        assert "user" not in result

    def test_hostname_depth_controllable_with_max_dots_directive(self, socket):
        # This config sets MaxDots of 2, so now canonicalization occurs
        result = load_config("deep-canon-maxdots").lookup("subber.sub.www")
        assert result["hostname"] == "subber.sub.www.paramiko.org"
        assert result["user"] == "deeper"

    def test_max_dots_may_be_zero(self, socket):
        result = load_config("zero-maxdots").lookup("sub.www")
        assert result["hostname"] == "sub.www"
        assert "user" not in result

    def test_fallback_yes_does_not_canonicalize_or_error(self, socket):
        socket.gethostbyname.side_effect = socket.gaierror
        result = load_config("fallback-yes").lookup("www")
        assert result["hostname"] == "www"
        assert "user" not in result

    def test_fallback_no_causes_errors_for_unresolvable_names(self, socket):
        socket.gethostbyname.side_effect = socket.gaierror
        with raises(CouldNotCanonicalize) as info:
            load_config("fallback-no").lookup("doesnotexist")
        assert str(info.value) == "doesnotexist"

    def test_identityfile_continues_being_appended_to(self, socket):
        result = load_config("canon").lookup("www")
        assert result["identityfile"] == ["base.key", "canonicalized.key"]


@mark.skip
class TestCanonicalizationOfCNAMEs:
    def test_permitted_cnames_may_be_one_to_one_mapping(self):
        # CanonicalizePermittedCNAMEs *.foo.com:*.bar.com
        pass

    def test_permitted_cnames_may_be_one_to_many_mapping(self):
        # CanonicalizePermittedCNAMEs *.foo.com:*.bar.com,*.biz.com
        pass

    def test_permitted_cnames_may_be_many_to_one_mapping(self):
        # CanonicalizePermittedCNAMEs *.foo.com,*.bar.com:*.biz.com
        pass

    def test_permitted_cnames_may_be_many_to_many_mapping(self):
        # CanonicalizePermittedCNAMEs *.foo.com,*.bar.com:*.biz.com,*.baz.com
        pass

    def test_permitted_cnames_may_be_multiple_mappings(self):
        # CanonicalizePermittedCNAMEs *.foo.com,*.bar.com *.biz.com:*.baz.com
        pass

    def test_permitted_cnames_may_be_multiple_complex_mappings(self):
        # Same as prev but with multiple patterns on both ends in both args
        pass


class TestMatchAll:
    def test_always_matches(self):
        result = load_config("match-all").lookup("general")
        assert result["user"] == "awesome"

    def test_may_not_mix_with_non_canonical_keywords(self):
        for config in ("match-all-and-more", "match-all-and-more-before"):
            with raises(ConfigParseError):
                load_config(config).lookup("whatever")

    def test_may_come_after_canonical(self, socket):
        result = load_config("match-all-after-canonical").lookup("www")
        assert result["user"] == "awesome"

    def test_may_not_come_before_canonical(self, socket):
        with raises(ConfigParseError):
            load_config("match-all-before-canonical")

    def test_after_canonical_not_loaded_when_non_canonicalized(self, socket):
        result = load_config("match-canonical-no").lookup("a-host")
        assert "user" not in result


def _expect(success_on):
    """
    Returns a side_effect-friendly Invoke success result for given command(s).

    Ensures that any other commands fail; this is useful for testing 'Match
    exec' because it means all other such clauses under test act like no-ops.

    :param success_on:
        Single string or list of strings, noting commands that should appear to
        succeed.
    """
    if isinstance(success_on, str):
        success_on = [success_on]

    def inner(command, *args, **kwargs):
        # Sanity checking - we always expect that invoke.run is called with
        # these.
        assert kwargs.get("hide", None) == "stdout"
        assert kwargs.get("warn", None) is True
        # Fake exit
        exit = 0 if command in success_on else 1
        return Result(exited=exit)

    return inner


@mark.skipif(Result is None, reason="requires invoke package")
class TestMatchExec:
    @patch("paramiko.config.invoke", new=None)
    @patch("paramiko.config.invoke_import_error", new=ImportError("meh"))
    def test_raises_invoke_ImportErrors_at_runtime(self):
        # Not an ideal test, but I don't know of a non-bad way to fake out
        # module-time ImportErrors. So we mock the symptoms. Meh!
        with raises(ImportError) as info:
            load_config("match-exec").lookup("oh-noes")
        assert str(info.value) == "meh"

    @patch("paramiko.config.invoke.run")
    @mark.parametrize(
        "cmd,user",
        [
            ("unquoted", "rando"),
            ("quoted", "benjamin"),
            ("quoted spaced", "neil"),
        ],
    )
    def test_accepts_single_possibly_quoted_argument(self, run, cmd, user):
        run.side_effect = _expect(cmd)
        result = load_config("match-exec").lookup("whatever")
        assert result["user"] == user

    @patch("paramiko.config.invoke.run")
    def test_does_not_match_nonzero_exit_codes(self, run):
        # Nothing will succeed -> no User ever gets loaded
        run.return_value = Result(exited=1)
        result = load_config("match-exec").lookup("whatever")
        assert "user" not in result

    @patch("paramiko.config.getpass")
    @patch("paramiko.config.invoke.run")
    def test_tokenizes_argument(self, run, getpass, socket):
        getpass.getuser.return_value = "gandalf"
        # Actual exec value is "%C %d %h %L %l %n %p %r %u"
        parts = (
            "bf5ba06778434a9384ee4217e462f64888bd0cd2",
            expanduser("~"),
            "configured",
            "local",
            "some.fake.fqdn",
            "target",
            "22",
            "intermediate",
            "gandalf",
        )
        run.side_effect = _expect(" ".join(parts))
        result = load_config("match-exec").lookup("target")
        assert result["port"] == "1337"

    @patch("paramiko.config.invoke.run")
    def test_works_with_canonical(self, run, socket):
        # Ensure both stanzas' exec components appear to match
        run.side_effect = _expect(["uncanonicalized", "canonicalized"])
        result = load_config("match-exec-canonical").lookup("who-cares")
        # Prove both config values got loaded up, across the two passes
        assert result["user"] == "defenseless"
        assert result["port"] == "8007"

    @patch("paramiko.config.invoke.run")
    def test_may_be_negated(self, run):
        run.side_effect = _expect("this succeeds")
        result = load_config("match-exec-negation").lookup("so-confusing")
        # If negation did not work, the first of the two Match exec directives
        # would have set User to 'nope' (and/or the second would have NOT set
        # User to 'yup')
        assert result["user"] == "yup"

    def test_requires_an_argument(self):
        with raises(ConfigParseError):
            load_config("match-exec-no-arg")

    @patch("paramiko.config.invoke.run")
    def test_works_with_tokenized_hostname(self, run):
        run.side_effect = _expect("ping target")
        result = load_config("hostname-exec-tokenized").lookup("target")
        assert result["hostname"] == "pingable.target"


class TestMatchHost:
    def test_matches_target_name_when_no_hostname(self):
        result = load_config("match-host").lookup("target")
        assert result["user"] == "rand"

    def test_matches_hostname_from_global_setting(self):
        # Also works for ones set in regular Host stanzas
        result = load_config("match-host-name").lookup("anything")
        assert result["user"] == "silly"

    def test_matches_hostname_from_earlier_match(self):
        # Corner case: one Match matches original host, sets HostName,
        # subsequent Match matches the latter.
        result = load_config("match-host-from-match").lookup("original-host")
        assert result["user"] == "inner"

    def test_may_be_globbed(self):
        result = load_config("match-host-glob-list").lookup("whatever")
        assert result["user"] == "matrim"

    def test_may_be_comma_separated_list(self):
        for target in ("somehost", "someotherhost"):
            result = load_config("match-host-glob-list").lookup(target)
            assert result["user"] == "thom"

    def test_comma_separated_list_may_have_internal_negation(self):
        conf = load_config("match-host-glob-list")
        assert conf.lookup("good")["user"] == "perrin"
        assert "user" not in conf.lookup("goof")

    def test_matches_canonicalized_name(self, socket):
        # Without 'canonical' explicitly declared, mind.
        result = load_config("match-host-canonicalized").lookup("www")
        assert result["user"] == "rand"

    def test_works_with_canonical_keyword(self, socket):
        # NOTE: distinct from 'happens to be canonicalized' above
        result = load_config("match-host-canonicalized").lookup("docs")
        assert result["user"] == "eric"

    def test_may_be_negated(self):
        conf = load_config("match-host-negated")
        assert conf.lookup("docs")["user"] == "jeff"
        assert "user" not in conf.lookup("www")

    def test_requires_an_argument(self):
        with raises(ConfigParseError):
            load_config("match-host-no-arg")


class TestMatchOriginalHost:
    def test_matches_target_host_not_hostname(self):
        result = load_config("match-orighost").lookup("target")
        assert result["hostname"] == "bogus"
        assert result["user"] == "tuon"

    def test_matches_target_host_not_canonicalized_name(self, socket):
        result = load_config("match-orighost-canonical").lookup("www")
        assert result["hostname"] == "www.paramiko.org"
        assert result["user"] == "tuon"

    def test_may_be_globbed(self):
        result = load_config("match-orighost").lookup("whatever")
        assert result["user"] == "matrim"

    def test_may_be_comma_separated_list(self):
        for target in ("comma", "separated"):
            result = load_config("match-orighost").lookup(target)
            assert result["user"] == "chameleon"

    def test_comma_separated_list_may_have_internal_negation(self):
        result = load_config("match-orighost").lookup("nope")
        assert "user" not in result

    def test_may_be_negated(self):
        result = load_config("match-orighost").lookup("docs")
        assert result["user"] == "thom"

    def test_requires_an_argument(self):
        with raises(ConfigParseError):
            load_config("match-orighost-no-arg")


class TestMatchUser:
    def test_matches_configured_username(self):
        result = load_config("match-user-explicit").lookup("anything")
        assert result["hostname"] == "dumb"

    @patch("paramiko.config.getpass.getuser")
    def test_matches_local_username_by_default(self, getuser):
        getuser.return_value = "gandalf"
        result = load_config("match-user").lookup("anything")
        assert result["hostname"] == "gondor"

    @patch("paramiko.config.getpass.getuser")
    def test_may_be_globbed(self, getuser):
        for user in ("bilbo", "bombadil"):
            getuser.return_value = user
            result = load_config("match-user").lookup("anything")
            assert result["hostname"] == "shire"

    @patch("paramiko.config.getpass.getuser")
    def test_may_be_comma_separated_list(self, getuser):
        for user in ("aragorn", "frodo"):
            getuser.return_value = user
            result = load_config("match-user").lookup("anything")
            assert result["hostname"] == "moria"

    @patch("paramiko.config.getpass.getuser")
    def test_comma_separated_list_may_have_internal_negation(self, getuser):
        getuser.return_value = "legolas"
        result = load_config("match-user").lookup("anything")
        assert "port" not in result
        getuser.return_value = "gimli"
        result = load_config("match-user").lookup("anything")
        assert result["port"] == "7373"

    @patch("paramiko.config.getpass.getuser")
    def test_may_be_negated(self, getuser):
        getuser.return_value = "saruman"
        result = load_config("match-user").lookup("anything")
        assert result["hostname"] == "mordor"

    def test_requires_an_argument(self):
        with raises(ConfigParseError):
            load_config("match-user-no-arg")


# NOTE: highly derivative of previous suite due to the former's use of
# localuser fallback. Doesn't seem worth conflating/refactoring right now.
class TestMatchLocalUser:
    @patch("paramiko.config.getpass.getuser")
    def test_matches_local_username(self, getuser):
        getuser.return_value = "gandalf"
        result = load_config("match-localuser").lookup("anything")
        assert result["hostname"] == "gondor"

    @patch("paramiko.config.getpass.getuser")
    def test_may_be_globbed(self, getuser):
        for user in ("bilbo", "bombadil"):
            getuser.return_value = user
            result = load_config("match-localuser").lookup("anything")
            assert result["hostname"] == "shire"

    @patch("paramiko.config.getpass.getuser")
    def test_may_be_comma_separated_list(self, getuser):
        for user in ("aragorn", "frodo"):
            getuser.return_value = user
            result = load_config("match-localuser").lookup("anything")
            assert result["hostname"] == "moria"

    @patch("paramiko.config.getpass.getuser")
    def test_comma_separated_list_may_have_internal_negation(self, getuser):
        getuser.return_value = "legolas"
        result = load_config("match-localuser").lookup("anything")
        assert "port" not in result
        getuser.return_value = "gimli"
        result = load_config("match-localuser").lookup("anything")
        assert result["port"] == "7373"

    @patch("paramiko.config.getpass.getuser")
    def test_may_be_negated(self, getuser):
        getuser.return_value = "saruman"
        result = load_config("match-localuser").lookup("anything")
        assert result["hostname"] == "mordor"

    def test_requires_an_argument(self):
        with raises(ConfigParseError):
            load_config("match-localuser-no-arg")


class TestComplexMatching:
    # NOTE: this is still a cherry-pick of a few levels of complexity, there's
    # no point testing literally all possible combinations.

    def test_originalhost_host(self):
        result = load_config("match-complex").lookup("target")
        assert result["hostname"] == "bogus"
        assert result["user"] == "rand"

    @patch("paramiko.config.getpass.getuser")
    def test_originalhost_localuser(self, getuser):
        getuser.return_value = "rando"
        result = load_config("match-complex").lookup("remote")
        assert result["user"] == "calrissian"

    @patch("paramiko.config.getpass.getuser")
    def test_everything_but_all(self, getuser):
        getuser.return_value = "rando"
        result = load_config("match-complex").lookup("www")
        assert result["port"] == "7777"

    @patch("paramiko.config.getpass.getuser")
    def test_everything_but_all_with_some_negated(self, getuser):
        getuser.return_value = "rando"
        result = load_config("match-complex").lookup("docs")
        assert result["port"] == "1234"

    def test_negated_canonical(self, socket):
        # !canonical in a config that is not canonicalized - does match
        result = load_config("match-canonical-no").lookup("specific")
        assert result["user"] == "overload"
        # !canonical in a config that is canonicalized - does NOT match
        result = load_config("match-canonical-yes").lookup("www")
        assert result["user"] == "hidden"
