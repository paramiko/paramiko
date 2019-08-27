# This file is part of Paramiko and subject to the license in /LICENSE in this
# repository

from os.path import expanduser
from socket import gaierror

from mock import patch
from pytest import raises, mark, fixture

from paramiko import SSHConfig, SSHConfigDict, CouldNotCanonicalize
from paramiko.util import lookup_ssh_host_config

from .util import _config


def load_config(name):
    return SSHConfig.from_path(_config(name))


class TestSSHConfig(object):
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

    def test_host_config(self):
        for host, values in {
            "irc.danger.com": {
                "crazy": "something dumb",
                "hostname": "irc.danger.com",
                "user": "robey",
            },
            "irc.example.com": {
                "crazy": "something dumb",
                "hostname": "irc.example.com",
                "user": "robey",
                "port": "3333",
            },
            "spoo.example.com": {
                "crazy": "something dumb",
                "hostname": "spoo.example.com",
                "user": "robey",
                "port": "3333",
            },
        }.items():
            values = dict(
                values,
                hostname=host,
                identityfile=[expanduser("~/.ssh/id_rsa")],
            )
            assert lookup_ssh_host_config(host, self.config) == values

    def test_host_config_expose_fabric_issue_33(self):
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
        assert lookup_ssh_host_config(host, config) == expected

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
            value = lookup_ssh_host_config(host, config)["proxycommand"]
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
            assert lookup_ssh_host_config(host, config)["proxycommand"] == val

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
        got = lookup_ssh_host_config("test", config)["proxycommand"]
        assert got == expected

    def test_host_config_test_negation(self):
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
        assert lookup_ssh_host_config(host, config) == expected

    def test_host_config_test_proxycommand(self):
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

            assert lookup_ssh_host_config(host, config) == values

    def test_host_config_test_identityfile(self):
        config = SSHConfig.from_text(
            """

IdentityFile id_dsa0

Host *
IdentityFile id_dsa1

Host dsa2
IdentityFile id_dsa2

Host dsa2*
IdentityFile id_dsa22
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
        }.items():

            assert lookup_ssh_host_config(host, config) == values

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
            assert lookup_ssh_host_config(host, config) == values

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
            assert lookup_ssh_host_config(host, config) == values

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
            with raises(Exception):
                conf._get_hosts(host)

    def test_proxycommand_none_issue_418(self):
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
                "hostname": "proxycommand-standard-none"
            },
            "proxycommand-with-equals-none": {
                "hostname": "proxycommand-with-equals-none"
            },
        }.items():

            assert lookup_ssh_host_config(host, config) == values

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
        # When bug is present, the full stripping-out of specific-host's
        # ProxyCommand means it actually appears to pick up the default
        # ProxyCommand value instead, due to cascading. It should (for
        # backwards compatibility reasons in 1.x/2.x) appear completely blank,
        # as if the host had no ProxyCommand whatsoever.
        # Threw another unrelated host in there just for sanity reasons.
        assert "proxycommand" not in config.lookup("specific-host")
        assert config.lookup("other-host")["proxycommand"] == "other-proxy"
        cmd = config.lookup("some-random-host")["proxycommand"]
        assert cmd == "default-proxy"


class TestSSHConfigDict(object):
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


@fixture
def socket():
    with patch("paramiko.config.socket") as mocket:
        # Reinstate gaierror as an actual exception and not a sub-mock.
        # (Presumably this would work with any exception, but why not use the
        # real one?)
        mocket.gaierror = gaierror
        # Patch out getaddrinfo, used to detect family-specific IP lookup -
        # only useful for a few specific tests.
        mocket.getaddrinfo.side_effect = mocket.gaierror
        yield mocket


class TestHostnameCanonicalization(object):
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
class TestCanonicalizationOfCNAMEs(object):
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
