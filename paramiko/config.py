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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Configuration file (aka ``ssh_config``) support.
"""

import fnmatch
import os
import re
import shlex
import socket

from .py3compat import StringIO

from .ssh_exception import CouldNotCanonicalize


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
        host = {"host": ["*"], "config": {}}
        for line in file_obj:
            # Strip any leading or trailing whitespace from the line.
            # Refer to https://github.com/paramiko/paramiko/issues/499
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = re.match(self.SETTINGS_REGEX, line)
            if not match:
                raise Exception("Unparsable line {}".format(line))
            key = match.group(1).lower()
            value = match.group(2)

            if key == "host":
                self._config.append(host)
                host = {"host": self._get_hosts(value), "config": {}}
            elif key == "proxycommand" and value.lower() == "none":
                # Store 'none' as None; prior to 3.x, it will get stripped out
                # at the end (for compatibility with issue #415). After 3.x, it
                # will simply not get stripped, leaving a nice explicit marker.
                host["config"][key] = None
            else:
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                # identityfile, localforward, remoteforward keys are special
                # cases, since they are allowed to be specified multiple times
                # and they should be tried in order of specification.
                if key in ["identityfile", "localforward", "remoteforward"]:
                    if key in host["config"]:
                        host["config"][key].append(value)
                    else:
                        host["config"][key] = [value]
                elif key not in host["config"]:
                    host["config"][key] = value
        self._config.append(host)

    def lookup(self, hostname):
        """
        Return a dict (`SSHConfigDict`) of config options for a given hostname.

        The host-matching rules of OpenSSH's ``ssh_config`` man page are used:
        For each parameter, the first obtained value will be used.  The
        configuration files contain sections separated by ``Host``
        specifications, and that section is only applied for hosts that match
        one of the patterns given in the specification.

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

        :param str hostname: the hostname to lookup

        .. versionchanged:: 2.5
            Returns `SSHConfigDict` objects instead of dict literals.
        .. versionchanged:: 2.7
            Added canonicalization support.
        """
        # First pass
        options = self._lookup(hostname=hostname)
        # Handle canonicalization
        canon = options.get("canonicalizehostname", None) in ("yes", "always")
        maxdots = int(options.get("canonicalizemaxdots", 1))
        if canon and hostname.count(".") <= maxdots:
            # NOTE: OpenSSH manpage does not explicitly state this, but its
            # implementation for CanonicalDomains is 'split on any whitespace'.
            domains = options["canonicaldomains"].split()
            hostname = self.canonicalize(hostname, options, domains)
            options["hostname"] = hostname
            options = self._lookup(hostname, options)
        return options

    def _lookup(self, hostname, options=None):
        matches = [
            config
            for config in self._config
            if self._allowed(config["host"], hostname)
        ]

        if options is None:
            options = SSHConfigDict()
        for match in matches:
            for key, value in match["config"].items():
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

    def _allowed(self, hosts, hostname):
        match = False
        for host in hosts:
            if host.startswith("!") and fnmatch.fnmatch(hostname, host[1:]):
                return False
            elif fnmatch.fnmatch(hostname, host):
                match = True
        return match

    def _expand_variables(self, config, hostname):
        """
        Return a dict of config options with expanded substitutions
        for a given hostname.

        Please refer to man ``ssh_config`` for the parameters that
        are replaced.

        :param dict config: the config for the hostname
        :param str hostname: the hostname that the config belongs to
        """

        if "hostname" in config:
            config["hostname"] = config["hostname"].replace("%h", hostname)
        else:
            config["hostname"] = hostname

        if "port" in config:
            port = config["port"]
        else:
            port = SSH_PORT

        user = os.getenv("USER")
        if "user" in config:
            remoteuser = config["user"]
        else:
            remoteuser = user

        host = socket.gethostname().split(".")[0]
        fqdn = LazyFqdn(config, host)
        homedir = os.path.expanduser("~")
        replacements = {
            "controlpath": [
                ("%h", config["hostname"]),
                ("%l", fqdn),
                ("%L", host),
                ("%n", hostname),
                ("%p", port),
                ("%r", remoteuser),
                ("%u", user),
            ],
            "identityfile": [
                ("~", homedir),
                ("%d", homedir),
                ("%h", config["hostname"]),
                ("%l", fqdn),
                ("%u", user),
                ("%r", remoteuser),
            ],
            "proxycommand": [
                ("~", homedir),
                ("%h", config["hostname"]),
                ("%p", port),
                ("%r", remoteuser),
            ],
        }

        for k in config:
            if config[k] is None:
                continue
            if k in replacements:
                for find, replace in replacements[k]:
                    if isinstance(config[k], list):
                        for item in range(len(config[k])):
                            if find in config[k][item]:
                                config[k][item] = config[k][item].replace(
                                    find, str(replace)
                                )
                    else:
                        if find in config[k]:
                            config[k] = config[k].replace(find, str(replace))
        return config

    def _get_hosts(self, host):
        """
        Return a list of host_names from host value.
        """
        try:
            return shlex.split(host)
        except ValueError:
            raise Exception("Unparsable host {}".format(host))


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
