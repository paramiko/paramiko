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
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
L{SSHConfig}.
"""

import fnmatch
import os
import re
import socket

SSH_PORT = 22
proxy_re = re.compile(r"^(proxycommand)\s*=*\s*(.*)", re.I)


class LazyFqdn(object):
    """
    Returns the host's fqdn on request as string.
    """

    def __init__(self, config):
        self.fqdn = None
        self.config = config

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
            address_family = self.config.get('addressfamily', 'any').lower()
            if address_family != 'any':
                family = socket.AF_INET if address_family == 'inet' \
                    else socket.AF_INET6
                results = socket.getaddrinfo(host,
                                             None,
                                             family,
                                             socket.SOCK_DGRAM,
                                             socket.IPPROTO_IP,
                                             socket.AI_CANONNAME)
                for res in results:
                    af, socktype, proto, canonname, sa = res
                    if canonname and '.' in canonname:
                        fqdn = canonname
                        break
            # Handle 'any' / unspecified
            if fqdn is None:
                fqdn = socket.getfqdn()
            # Cache
            self.fqdn = fqdn
        return self.fqdn


class SSHConfig (object):
    """
    Representation of config information as stored in the format used by
    OpenSSH. Queries can be made via L{lookup}. The format is described in
    OpenSSH's C{ssh_config} man page. This class is provided primarily as a
    convenience to posix users (since the OpenSSH format is a de-facto
    standard on posix) but should work fine on Windows too.

    @since: 1.6
    """

    def __init__(self):
        """
        Create a new OpenSSH config object.
        """
        self._config = []

    def parse(self, file_obj):
        """
        Read an OpenSSH config from the given file object.

        @param file_obj: a file-like object to read the config file from
        @type file_obj: file
        """
        host = {"host": ['*'], "config": {}}
        for line in file_obj:
            line = line.rstrip('\n').lstrip()
            if (line == '') or (line[0] == '#'):
                continue
            if '=' in line:
                # Ensure ProxyCommand gets properly split
                if line.lower().strip().startswith('proxycommand'):
                    match = proxy_re.match(line)
                    key, value = match.group(1).lower(), match.group(2)
                else:
                    key, value = line.split('=', 1)
                    key = key.strip().lower()
            else:
                # find first whitespace, and split there
                i = 0
                while (i < len(line)) and not line[i].isspace():
                    i += 1
                if i == len(line):
                    raise Exception('Unparsable line: %r' % line)
                key = line[:i].lower()
                value = line[i:].lstrip()

            if key == 'host':
                self._config.append(host)
                value = value.split()
                host = {key: value, 'config': {}}
            #identityfile is a special case, since it is allowed to be
            # specified multiple times and they should be tried in order
            # of specification.
            elif key == 'identityfile':
                if key in host['config']:
                    host['config']['identityfile'].append(value)
                else:
                    host['config']['identityfile'] = [value]
            elif key not in host['config']:
                    host['config'].update({key: value})
        self._config.append(host)

    def lookup(self, hostname):
        """
        Return a dict of config options for a given hostname.

        The host-matching rules of OpenSSH's C{ssh_config} man page are used,
        which means that all configuration options from matching host
        specifications are merged, with more specific hostmasks taking
        precedence. In other words, if C{"Port"} is set under C{"Host *"}
        and also C{"Host *.example.com"}, and the lookup is for
        C{"ssh.example.com"}, then the port entry for C{"Host *.example.com"}
        will win out.

        The keys in the returned dict are all normalized to lowercase (look for
        C{"port"}, not C{"Port"}. The values are processed according to the
        rules for substitution variable expansion in C{ssh_config}.

        @param hostname: the hostname to lookup
        @type hostname: str
        """

        matches = [config for config in self._config if
                   self._allowed(hostname, config['host'])]

        ret = {}
        for match in matches:
            for key, value in match['config'].iteritems():
                if key not in ret:
                    # Create a copy of the original value,
                    # else it will reference the original list
                    # in self._config and update that value too
                    # when the extend() is being called.
                    ret[key] = value[:]
                elif key == 'identityfile':
                    ret[key].extend(value)
        ret = self._expand_variables(ret, hostname)
        return ret

    def _allowed(self, hostname, hosts):
        match = False
        for host in hosts:
            if host.startswith('!') and fnmatch.fnmatch(hostname, host[1:]):
                return False
            elif fnmatch.fnmatch(hostname, host):
                match = True
        return match

    def _expand_variables(self, config, hostname):
        """
        Return a dict of config options with expanded substitutions
        for a given hostname.

        Please refer to man C{ssh_config} for the parameters that
        are replaced.

        @param config: the config for the hostname
        @type hostname: dict
        @param hostname: the hostname that the config belongs to
        @type hostname: str
        """

        if 'hostname' in config:
            config['hostname'] = config['hostname'].replace('%h', hostname)
        else:
            config['hostname'] = hostname

        if 'port' in config:
            port = config['port']
        else:
            port = SSH_PORT

        user = os.getenv('USER')
        if 'user' in config:
            remoteuser = config['user']
        else:
            remoteuser = user

        host = socket.gethostname().split('.')[0]
        fqdn = LazyFqdn(config)
        homedir = os.path.expanduser('~')
        replacements = {'controlpath':
                        [
                            ('%h', config['hostname']),
                            ('%l', fqdn),
                            ('%L', host),
                            ('%n', hostname),
                            ('%p', port),
                            ('%r', remoteuser),
                            ('%u', user)
                        ],
                        'identityfile':
                        [
                            ('~', homedir),
                            ('%d', homedir),
                            ('%h', config['hostname']),
                            ('%l', fqdn),
                            ('%u', user),
                            ('%r', remoteuser)
                        ],
                        'proxycommand':
                        [
                            ('%h', config['hostname']),
                            ('%p', port),
                            ('%r', remoteuser)
                        ]
                        }

        for k in config:
            if k in replacements:
                for find, replace in replacements[k]:
                    if isinstance(config[k], list):
                        for item in range(len(config[k])):
                            config[k][item] = config[k][item].\
                                replace(find, str(replace))
                    else:
                            config[k] = config[k].replace(find, str(replace))
        return config
