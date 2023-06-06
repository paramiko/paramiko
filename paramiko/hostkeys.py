# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
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
from base64 import encodebytes, decodebytes
import binascii
import os
import re

from collections.abc import MutableMapping
from collections import defaultdict
from hashlib import sha1
from hmac import HMAC
from itertools import chain
import math

from paramiko.pkey import PKey, UnknownKeyType
from paramiko.util import get_logger, constant_time_bytes_eq, b, u
from paramiko.ssh_exception import SSHException


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = defaultdict(list)
        self._hashed_entries = []
        if filename is not None:
            self.load(filename)

    @staticmethod
    def _is_hashed(hostname):
        """
        Determine if a hostname is hashed.

        :param str hostname: the hostname to check
        """
        return hostname.startswith("|1|")

    def _entries_for_hostname(self, hostname):
        """
        Helper function to get the collection a hostname belongs to

        :param str hostname: the hostname
        """
        if self._is_hashed(hostname):
            return self._hashed_entries
        return self._entries[hostname]

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (``"ssh-rsa"`` or ``"ssh-dss"``)
        :param .PKey key: the key to add
        """
        entries = self._entries_for_hostname(hostname)
        for e in entries:
            if (hostname in e.hostnames) and (e.key.get_name() == keytype):
                e.key = key
                return
        entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except SSHException:
                    continue
                if entry is not None:
                    _hostnames = entry.hostnames
                    for h in _hostnames:
                        if self.check(h, entry.key):
                            entry.hostnames.remove(h)
                    if len(entry.hostnames):
                        for hostname in entry.hostnames:
                            self._entries_for_hostname(hostname).append(entry)

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            all_entries = set(chain(*self._entries.values(), self._hashed_entries))

            # Entries without a line number should be appended to the known_hosts
            # file, since they were added after loading the file, e.g. with add()
            # or AutoAddPolicy or similar.
            for entry in sorted(all_entries, key=lambda e: e.lineno or math.inf):
                line = entry.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.  The keytype will be either ``"ssh-rsa"`` or ``"ssh-dss"``.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    e = HostKeyEntry([hostname], val)
                    self._entries.append(e)
                    self._hostkeys._entries[hostname].append(e)

            def keys(self):
                return [e.key.get_name() for e in self._entries if e.key is not None]

        entries = []
        for e in chain(self._entries[hostname], self._hashed_entries):
            if self._hostname_matches(hostname, e):
                entries.append(e)
        if len(entries) == 0:
            return None
        return SubDict(hostname, entries, self)

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        :returns bool:
        """
        for h in entry.hostnames:
            if (
                h == hostname
                or self._is_hashed(h)
                and not self._is_hashed(hostname)
                and constant_time_bytes_eq(self.hash_host(hostname, h), h)
            ):
                return True
        return False

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = defaultdict(list)
        self._hashed_entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        entries = self._entries_for_hostname(key)
        for i, entry in enumerate(entries):
            if self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        entries = self._entries_for_hostname(hostname)
        if len(entry) == 0:
            entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in entries:
                if (hostname in e.hostnames) and e.key.get_name() == key_type:
                    # replace
                    e.key = entry[key_type]
                    found = True
            if not found:
                entries.append(HostKeyEntry([hostname], entry[key_type]))

    def keys(self):
        return [key for key, entries in self._entries.items() if entries] + [
            hostname for entry in self._hashed_entries for hostname in entry.hostnames
        ]

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None, lineno=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key
        self.lineno = lineno

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        fields = re.split(" |\t", line)
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None
        fields = fields[:3]

        names, key_type, key = fields
        names = names.split(",")

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise InvalidHostKey(line, e)

        try:
            return cls(names, PKey.from_type_string(key_type, key_bytes), lineno)
        except UnknownKeyType:
            # TODO 4.0: consider changing HostKeys API so this just raises
            # naturally and the exception is muted higher up in the stack?
            log.info("Unable to handle key of type {}".format(key_type))
            return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if self.valid:
            return "{} {} {}\n".format(
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
