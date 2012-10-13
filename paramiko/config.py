# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
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
import socket

SSH_PORT=22

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
        self._matches = {}

    def parse(self, file_obj):
        """
        Read an OpenSSH config from the given file object.

        @param file_obj: a file-like object to read the config file from
        @type file_obj: file
        """
        host = Host('*')
        for line in file_obj:
            line = line.rstrip('\n').lstrip()
            if (line == '') or (line[0] == '#'):
                continue
            if '=' in line:
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
                host.register(self) #Register the previous host entry.
                host = Host(value)
            else:
                host[key] = value

    def register(self, hostname, host):
        """
        Registers a host configuration to a given hostname.

        There can exist multiple host configuraions for a single hostname.

        @param hostname: the hostname to register
        @type hostname: str
        @param host: the host configuration to register
        @type host: object
        """
        if hostname in self._matches:
            self._matches[hostname].append(host)
        else:
            self._matches[hostname] = [host]

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
        matches = [self._matches[x] for x in self._matches if
                  fnmatch.fnmatch(hostname,x)]

        # sort in order of shortest match (usually '*') to longest
        matches.sort(lambda x,y: cmp(len(x), len(y)))

        ret = {}
        for match in matches:
            for config in match:
                if config.allowed(hostname):
                    ret.update(config)
        ret = self._expand_variables(ret, hostname)
        return ret

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
            config['hostname'] = config['hostname'].replace('%h',hostname)
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
        fqdn = socket.getfqdn()
        homedir = os.path.expanduser('~')
        replacements = {'controlpath' :
                [
                    ('%h', config['hostname']),
                    ('%l', fqdn),
                    ('%L', host),
                    ('%n', hostname),
                    ('%p', port),
                    ('%r', remoteuser),
                    ('%u', user)
                ],
                'identityfile' :
                [
                    ('~', homedir),
                    ('%d', homedir),
                    ('%h', config['hostname']),
                    ('%l', fqdn),
                    ('%u', user),
                    ('%r', remoteuser)
                ]
                }
        for k in config:
            if k in replacements:
                for find, replace in replacements[k]:
                        config[k] = config[k].replace(find, str(replace))
        return config

class Host(dict):
    """
    Representation of a host configuration in a smart dictionary.
    This is an internal class subject to change. Consider it an
    implementation detail.
    """

    def __init__(self, hosts):
        """
        Create a new Host config object.

        @param hosts: a space separated string of hosts.
        @type hosts: str
        """
        super(Host, self).__init__()
        self._matches = []
        self._negations = []
        for host in hosts.split():
            if host.startswith("!"):
                self._negations.append(host[1:])
            else:
                self._matches.append(host)

    def __setitem__(self, key, value):
        super(Host, self).__setitem__(key, value)

    def __getitem__(self, key):
        return super(Host, self).__getitem__(key)

    def register(self, sshconfig):
        """
        Register this hosts matches in another object.

        @param sshconfig: an object that has a register method.
        @type sshconfig: object
        """
        for match in self._matches:
            sshconfig.register(match, self)

    def allowed(self, hostname):
        """
        Checks if the hostname matches a negation in the ssh_config
        for this host object.

        @param hostname: the hostname to match against negations.
        @type hosname: str
        """
        for negation in self._negations:
            if fnmatch.fnmatch(hostname, negation):
                return False
        return True
