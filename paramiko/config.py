# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
# Copyright (C) 2012  Olle Lundberg <geek@nerd.sh>
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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Configuration file (aka ``ssh_config``) support.
"""

import fnmatch
import getpass
import os
import re
import shlex
import socket
from hashlib import sha1
from functools import partial

from .py3compat import StringIO

invoke, invoke_import_error = None, None
try:
    import invoke
except ImportError as e:
    invoke_import_error = e

from .ssh_exception import CouldNotCanonicalize, ConfigParseError


SSH_PORT = 22


class SSHConfig(object):
    """
    Representation of config information as stored in the format used by
    OpenSSH. Queries can be made via `lookup`. The format is described in
    OpenSSH's ``ssh_config`` man page. This class is provided primarily as a
    convenience to posix users (since the OpenSSH format is a de-facto
    standard on posix) but should work fine on Windows too.

    .. versionadded:: 1.6
    """

    SETTINGS_REGEX = re.compile(r"(\w+)(?:\s*=\s*|\s+)(.+)")

    # TODO: do a full scan of ssh.c & friends to make sure we're fully
    # compatible across the board, e.g. OpenSSH 8.1 added %n to ProxyCommand.
    TOKENS_BY_CONFIG_KEY = {
        "controlpath": ["%C", "%h", "%l", "%L", "%n", "%p", "%r", "%u"],
        "hostname": ["%h"],
        "identityfile": ["%C", "~", "%d", "%h", "%l", "%u", "%r"],
        "proxycommand": ["~", "%h", "%p", "%r"],
        "proxyjump": ["%h", "%p", "%r"],
        # Doesn't seem worth making this 'special' for now, it will fit well
        # enough (no actual match-exec config key to be confused with).
        "match-exec": ["%C", "%d", "%h", "%L", "%l", "%n", "%p", "%r", "%u"],
    }

    def __init__(self):
        """
        Create a new OpenSSH config object.

        Note: the newer alternate constructors `from_path`, `from_file` and
        `from_text` are simpler to use, as they parse on instantiation. For
        example, instead of::

            config = SSHConfig()
            config.parse(open("some-path.config")

        you could::

            config = SSHConfig.from_file(open("some-path.config"))
            # Or more directly:
            config = SSHConfig.from_path("some-path.config")
            # Or if you have arbitrary ssh_config text from some other source:
            config = SSHConfig.from_text("Host foo\\n\\tUser bar")
        """
        self._config = []

    @classmethod
    def from_text(cls, text):
        """
        Create a new, parsed `SSHConfig` from ``text`` string.

        .. versionadded:: 2.7
        """
        return cls.from_file(StringIO(text))

    @classmethod
    def from_path(cls, path):
        """
        Create a new, parsed `SSHConfig` from the file found at ``path``.

        .. versionadded:: 2.7
        """
        with open(path) as flo:
            return cls.from_file(flo)

    @classmethod
    def from_file(cls, flo):
        """
        Create a new, parsed `SSHConfig` from file-like object ``flo``.

        .. versionadded:: 2.7
        """
        obj = cls()
        obj.parse(flo)
        return obj

    def parse(self, file_obj):
        """
        Read an OpenSSH config from the given file object.

        :param file_obj: a file-like object to read the config file from
        """
        # Start out w/ implicit/anonymous global host-like block to hold
        # anything not contained by an explicit one.
        context = {"host": ["*"], "config": {}}
        for line in file_obj:
            # Strip any leading or trailing whitespace from the line.
            # Refer to https://github.com/paramiko/paramiko/issues/499
            line = line.strip()
            # Skip blanks, comments
            if not line or line.startswith("#"):
                continue

            # Parse line into key, value
            match = re.match(self.SETTINGS_REGEX, line)
            if not match:
                raise ConfigParseError("Unparsable line {}".format(line))
            key = match.group(1).lower()
            value = match.group(2)

            # Host keyword triggers switch to new block/context
            if key in ("host", "match"):
                self._config.append(context)
                context = {"config": {}}
                if key == "host":
                    # TODO 3.0: make these real objects or at least name this
                    # "hosts" to acknowledge it's an iterable. (Doing so prior
                    # to 3.0, despite it being a private API, feels bad -
                    # surely such an old codebase has folks actually relying on
                    # these keys.)
                    context["host"] = self._get_hosts(value)
                else:
                    context["matches"] = self._get_matches(value)
            # Special-case for noop ProxyCommands
            elif key == "proxycommand" and value.lower() == "none":
                # Store 'none' as None; prior to 3.x, it will get stripped out
                # at the end (for compatibility with issue #415). After 3.x, it
                # will simply not get stripped, leaving a nice explicit marker.
                context["config"][key] = None
            # All other keywords get stored, directly or via append
            else:
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                # identityfile, localforward, remoteforward keys are special
                # cases, since they are allowed to be specified multiple times
                # and they should be tried in order of specification.
                if key in ["identityfile", "localforward", "remoteforward"]:
                    if key in context["config"]:
                        context["config"][key].append(value)
                    else:
                        context["config"][key] = [value]
                elif key not in context["config"]:
                    context["config"][key] = value
        # Store last 'open' block and we're done
        self._config.append(context)

    def lookup(self, hostname):
        """
        Return a dict (`SSHConfigDict`) of config options for a given hostname.

        The host-matching rules of OpenSSH's ``ssh_config`` man page are used:
        For each parameter, the first obtained value will be used.  The
        configuration files contain sections separated by ``Host`` and/or
        ``Match`` specifications, and that section is only applied for hosts
        which match the given patterns or keywords

        Since the first obtained value for each parameter is used, more host-
        specific declarations should be given near the beginning of the file,
        and general defaults at the end.

        The keys in the returned dict are all normalized to lowercase (look for
        ``"port"``, not ``"Port"``. The values are processed according to the
        rules for substitution variable expansion in ``ssh_config``.

        Finally, please see the docs for `SSHConfigDict` for deeper info on
        features such as optional type conversion methods, e.g.::

            conf = my_config.lookup('myhost')
            assert conf['passwordauthentication'] == 'yes'
            assert conf.as_bool('passwordauthentication') is True

        .. note::
            If there is no explicitly configured ``HostName`` value, it will be
            set to the being-looked-up hostname, which is as close as we can
            get to OpenSSH's behavior around that particular option.

        :param str hostname: the hostname to lookup

        .. versionchanged:: 2.5
            Returns `SSHConfigDict` objects instead of dict literals.
        .. versionchanged:: 2.7
            Added canonicalization support.
        .. versionchanged:: 2.7
            Added ``Match`` support.
        """
        # First pass
        options = self._lookup(hostname=hostname)
        # Inject HostName if it was not set (this used to be done incidentally
        # during tokenization, for some reason).
        if "hostname" not in options:
            options["hostname"] = hostname
        # Handle canonicalization
        canon = options.get("canonicalizehostname", None) in ("yes", "always")
        maxdots = int(options.get("canonicalizemaxdots", 1))
        if canon and hostname.count(".") <= maxdots:
            # NOTE: OpenSSH manpage does not explicitly state this, but its
            # implementation for CanonicalDomains is 'split on any whitespace'.
            domains = options["canonicaldomains"].split()
            hostname = self.canonicalize(hostname, options, domains)
            # Overwrite HostName again here (this is also what OpenSSH does)
            options["hostname"] = hostname
            options = self._lookup(hostname, options, canonical=True)
        return options

    def _lookup(self, hostname, options=None, canonical=False):
        # Init
        if options is None:
            options = SSHConfigDict()
        # Iterate all stanzas, applying any that match, in turn (so that things
        # like Match can reference currently understood state)
        for context in self._config:
            if not (
                self._pattern_matches(context.get("host", []), hostname)
                or self._does_match(
                    context.get("matches", []), hostname, canonical, options
                )
            ):
                continue
            for key, value in context["config"].items():
                if key not in options:
                    # Create a copy of the original value,
                    # else it will reference the original list
                    # in self._config and update that value too
                    # when the extend() is being called.
                    options[key] = value[:] if value is not None else value
                elif key == "identityfile":
                    options[key].extend(
                        x for x in value if x not in options[key]
                    )
        # Expand variables in resulting values (besides 'Match exec' which was
        # already handled above)
        options = self._expand_variables(options, hostname)
        # TODO: remove in 3.x re #670
        if "proxycommand" in options and options["proxycommand"] is None:
            del options["proxycommand"]
        return options

    def canonicalize(self, hostname, options, domains):
        """
        Return canonicalized version of ``hostname``.

        :param str hostname: Target hostname.
        :param options: An `SSHConfigDict` from a previous lookup pass.
        :param domains: List of domains (e.g. ``["paramiko.org"]``).

        :returns: A canonicalized hostname if one was found, else ``None``.

        .. versionadded:: 2.7
        """
        found = False
        for domain in domains:
            candidate = "{}.{}".format(hostname, domain)
            family_specific = _addressfamily_host_lookup(candidate, options)
            if family_specific is not None:
                # TODO: would we want to dig deeper into other results? e.g. to
                # find something that satisfies PermittedCNAMEs when that is
                # implemented?
                found = family_specific[0]
            else:
                # TODO: what does ssh use here and is there a reason to use
                # that instead of gethostbyname?
                try:
                    found = socket.gethostbyname(candidate)
                except socket.gaierror:
                    pass
            if found:
                # TODO: follow CNAME (implied by found != candidate?) if
                # CanonicalizePermittedCNAMEs allows it
                return candidate
        # If we got here, it means canonicalization failed.
        # When CanonicalizeFallbackLocal is undefined or 'yes', we just spit
        # back the original hostname.
        if options.get("canonicalizefallbacklocal", "yes") == "yes":
            return hostname
        # And here, we failed AND fallback was set to a non-yes value, so we
        # need to get mad.
        raise CouldNotCanonicalize(hostname)

    def get_hostnames(self):
        """
        Return the set of literal hostnames defined in the SSH config (both
        explicit hostnames and wildcard entries).
        """
        hosts = set()
        for entry in self._config:
            hosts.update(entry["host"])
        return hosts

    def _pattern_matches(self, patterns, target):
        # Convenience auto-splitter if not already a list
        if hasattr(patterns, "split"):
            patterns = patterns.split(",")
        match = False
        for pattern in patterns:
            # Short-circuit if target matches a negated pattern
            if pattern.startswith("!") and fnmatch.fnmatch(
                target, pattern[1:]
            ):
                return False
            # Flag a match, but continue (in case of later negation) if regular
            # match occurs
            elif fnmatch.fnmatch(target, pattern):
                match = True
        return match

    # TODO 3.0: remove entirely (is now unused internally)
    def _allowed(self, hosts, hostname):
        return self._pattern_matches(hosts, hostname)

    def _does_match(self, match_list, target_hostname, canonical, options):
        matched = []
        candidates = match_list[:]
        local_username = getpass.getuser()
        while candidates:
            candidate = candidates.pop(0)
            passed = None
            # Obtain latest host/user value every loop, so later Match may
            # reference values assigned within a prior Match.
            configured_host = options.get("hostname", None)
            configured_user = options.get("user", None)
            type_, param = candidate["type"], candidate["param"]
            # Canonical is a hard pass/fail based on whether this is a
            # canonicalized re-lookup.
            if type_ == "canonical":
                if self._should_fail(canonical, candidate):
                    return False
            # The parse step ensures we only see this by itself or after
            # canonical, so it's also an easy hard pass. (No negation here as
            # that would be uh, pretty weird?)
            elif type_ == "all":
                return True
            # From here, we are testing various non-hard criteria,
            # short-circuiting only on fail
            elif type_ == "host":
                hostval = configured_host or target_hostname
                passed = self._pattern_matches(param, hostval)
            elif type_ == "originalhost":
                passed = self._pattern_matches(param, target_hostname)
            elif type_ == "user":
                user = configured_user or local_username
                passed = self._pattern_matches(param, user)
            elif type_ == "localuser":
                passed = self._pattern_matches(param, local_username)
            elif type_ == "exec":
                exec_cmd = self._tokenize(
                    options, target_hostname, "match-exec", param
                )
                # This is the laziest spot in which we can get mad about an
                # inability to import Invoke.
                if invoke is None:
                    raise invoke_import_error
                # Like OpenSSH, we 'redirect' stdout but let stderr bubble up
                passed = invoke.run(exec_cmd, hide="stdout", warn=True).ok
            # Tackle any 'passed, but was negated' results from above
            if passed is not None and self._should_fail(passed, candidate):
                return False
            # Made it all the way here? Everything matched!
            matched.append(candidate)
        # Did anything match? (To be treated as bool, usually.)
        return matched

    def _should_fail(self, would_pass, candidate):
        return would_pass if candidate["negate"] else not would_pass

    def _tokenize(self, config, target_hostname, key, value):
        """
        Tokenize a string based on current config/hostname data.

        :param config: Current config data.
        :param target_hostname: Original target connection hostname.
        :param key: Config key being tokenized (used to filter token list).
        :param value: Config value being tokenized.

        :returns: The tokenized version of the input ``value`` string.
        """
        allowed_tokens = self._allowed_tokens(key)
        # Short-circuit if no tokenization possible
        if not allowed_tokens:
            return value
        # Obtain potentially configured hostname, for use with %h.
        # Special-case where we are tokenizing the hostname itself, to avoid
        # replacing %h with a %h-bearing value, etc.
        configured_hostname = target_hostname
        if key != "hostname":
            configured_hostname = config.get("hostname", configured_hostname)
        # Ditto the rest of the source values
        if "port" in config:
            port = config["port"]
        else:
            port = SSH_PORT
        user = getpass.getuser()
        if "user" in config:
            remoteuser = config["user"]
        else:
            remoteuser = user
        local_hostname = socket.gethostname().split(".")[0]
        local_fqdn = LazyFqdn(config, local_hostname)
        homedir = os.path.expanduser("~")
        tohash = local_hostname + target_hostname + repr(port) + remoteuser
        # The actual tokens!
        replacements = {
            # TODO: %%???
            "%C": sha1(tohash.encode()).hexdigest(),
            "%d": homedir,
            "%h": configured_hostname,
            # TODO: %i?
            "%L": local_hostname,
            "%l": local_fqdn,
            # also this is pseudo buggy when not in Match exec mode so document
            # that. also WHY is that the case?? don't we do all of this late?
            "%n": target_hostname,
            "%p": port,
            "%r": remoteuser,
            # TODO: %T? don't believe this is possible however
            "%u": user,
            "~": homedir,
        }
        # Do the thing with the stuff
        tokenized = value
        for find, replace in replacements.items():
            if find not in allowed_tokens:
                continue
            tokenized = tokenized.replace(find, str(replace))
        # TODO: log? eg that value -> tokenized
        return tokenized

    def _allowed_tokens(self, key):
        """
        Given config ``key``, return list of token strings to tokenize.

        .. note::
            This feels like it wants to eventually go away, but is used to
            preserve as-strict-as-possible compatibility with OpenSSH, which
            for whatever reason only applies some tokens to some config keys.
        """
        return self.TOKENS_BY_CONFIG_KEY.get(key, [])

    def _expand_variables(self, config, target_hostname):
        """
        Return a dict of config options with expanded substitutions
        for a given original & current target hostname.

        Please refer to :doc:`/api/config` for details.

        :param dict config: the currently parsed config
        :param str hostname: the hostname whose config is being looked up
        """
        for k in config:
            if config[k] is None:
                continue
            tokenizer = partial(self._tokenize, config, target_hostname, k)
            if isinstance(config[k], list):
                for i, value in enumerate(config[k]):
                    config[k][i] = tokenizer(value)
            else:
                config[k] = tokenizer(config[k])
        return config

    def _get_hosts(self, host):
        """
        Return a list of host_names from host value.
        """
        try:
            return shlex.split(host)
        except ValueError:
            raise ConfigParseError("Unparsable host {}".format(host))

    def _get_matches(self, match):
        """
        Parse a specific Match config line into a list-of-dicts for its values.

        Performs some parse-time validation as well.
        """
        matches = []
        tokens = shlex.split(match)
        while tokens:
            match = {"type": None, "param": None, "negate": False}
            type_ = tokens.pop(0)
            # Handle per-keyword negation
            if type_.startswith("!"):
                match["negate"] = True
                type_ = type_[1:]
            match["type"] = type_
            # all/canonical have no params (everything else does)
            if type_ in ("all", "canonical"):
                matches.append(match)
                continue
            if not tokens:
                raise ConfigParseError(
                    "Missing parameter to Match '{}' keyword".format(type_)
                )
            match["param"] = tokens.pop(0)
            matches.append(match)
        # Perform some (easier to do now than in the middle) validation that is
        # better handled here than at lookup time.
        keywords = [x["type"] for x in matches]
        if "all" in keywords:
            allowable = ("all", "canonical")
            ok, bad = (
                list(filter(lambda x: x in allowable, keywords)),
                list(filter(lambda x: x not in allowable, keywords)),
            )
            err = None
            if any(bad):
                err = "Match does not allow 'all' mixed with anything but 'canonical'"  # noqa
            elif "canonical" in ok and ok.index("canonical") > ok.index("all"):
                err = "Match does not allow 'all' before 'canonical'"
            if err is not None:
                raise ConfigParseError(err)
        return matches


def _addressfamily_host_lookup(hostname, options):
    """
    Try looking up ``hostname`` in an IPv4 or IPv6 specific manner.

    This is an odd duck due to needing use in two divergent use cases. It looks
    up ``AddressFamily`` in ``options`` and if it is ``inet`` or ``inet6``,
    this function uses `socket.getaddrinfo` to perform a family-specific
    lookup, returning the result if successful.

    In any other situation -- lookup failure, or ``AddressFamily`` being
    unspecified or ``any`` -- ``None`` is returned instead and the caller is
    expected to do something situation-appropriate like calling
    `socket.gethostbyname`.

    :param str hostname: Hostname to look up.
    :param options: `SSHConfigDict` instance w/ parsed options.
    :returns: ``getaddrinfo``-style tuples, or ``None``, depending.
    """
    address_family = options.get("addressfamily", "any").lower()
    if address_family == "any":
        return
    try:
        family = socket.AF_INET6
        if address_family == "inet":
            family = socket.AF_INET
        return socket.getaddrinfo(
            hostname,
            None,
            family,
            socket.SOCK_DGRAM,
            socket.IPPROTO_IP,
            socket.AI_CANONNAME,
        )
    except socket.gaierror:
        pass


class LazyFqdn(object):
    """
    Returns the host's fqdn on request as string.
    """

    def __init__(self, config, host=None):
        self.fqdn = None
        self.config = config
        self.host = host

    def __str__(self):
        if self.fqdn is None:
            #
            # If the SSH config contains AddressFamily, use that when
            # determining  the local host's FQDN. Using socket.getfqdn() from
            # the standard library is the most general solution, but can
            # result in noticeable delays on some platforms when IPv6 is
            # misconfigured or not available, as it calls getaddrinfo with no
            # address family specified, so both IPv4 and IPv6 are checked.
            #

            # Handle specific option
            fqdn = None
            results = _addressfamily_host_lookup(self.host, self.config)
            if results is not None:
                for res in results:
                    af, socktype, proto, canonname, sa = res
                    if canonname and "." in canonname:
                        fqdn = canonname
                        break
            # Handle 'any' / unspecified / lookup failure
            if fqdn is None:
                fqdn = socket.getfqdn()
            # Cache
            self.fqdn = fqdn
        return self.fqdn


class SSHConfigDict(dict):
    """
    A dictionary wrapper/subclass for per-host configuration structures.

    This class introduces some usage niceties for consumers of `SSHConfig`,
    specifically around the issue of variable type conversions: normal value
    access yields strings, but there are now methods such as `as_bool` and
    `as_int` that yield casted values instead.

    For example, given the following ``ssh_config`` file snippet::

        Host foo.example.com
            PasswordAuthentication no
            Compression yes
            ServerAliveInterval 60

    the following code highlights how you can access the raw strings as well as
    usefully Python type-casted versions (recalling that keys are all
    normalized to lowercase first)::

        my_config = SSHConfig()
        my_config.parse(open('~/.ssh/config'))
        conf = my_config.lookup('foo.example.com')

        assert conf['passwordauthentication'] == 'no'
        assert conf.as_bool('passwordauthentication') is False
        assert conf['compression'] == 'yes'
        assert conf.as_bool('compression') is True
        assert conf['serveraliveinterval'] == '60'
        assert conf.as_int('serveraliveinterval') == 60

    .. versionadded:: 2.5
    """

    def __init__(self, *args, **kwargs):
        # Hey, guess what? Python 2's userdict is an old-style class!
        super(SSHConfigDict, self).__init__(*args, **kwargs)

    def as_bool(self, key):
        """
        Express given key's value as a boolean type.

        Typically, this is used for ``ssh_config``'s pseudo-boolean values
        which are either ``"yes"`` or ``"no"``. In such cases, ``"yes"`` yields
        ``True`` and any other value becomes ``False``.

        .. note::
            If (for whatever reason) the stored value is already boolean in
            nature, it's simply returned.

        .. versionadded:: 2.5
        """
        val = self[key]
        if isinstance(val, bool):
            return val
        return val.lower() == "yes"

    def as_int(self, key):
        """
        Express given key's value as an integer, if possible.

        This method will raise ``ValueError`` or similar if the value is not
        int-appropriate, same as the builtin `int` type.

        .. versionadded:: 2.5
        """
        return int(self[key])
