# Copyright (C) 2006 Robey Pointer <robey@lag.net>
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
L{HostKeys}
"""

import base64
from Crypto.Hash import SHA, HMAC
import UserDict

from paramiko.common import *
from paramiko.dsskey import DSSKey
from paramiko.rsakey import RSAKey


class HostKeys (UserDict.DictMixin):
    """
    Representation of an openssh-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.
    
    A HostKeys object can be treated like a dict; any dict lookup is equivalent
    to calling L{lookup}.
    
    @since: 1.5.3
    """
    
    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an openssh
        style host-key file.
        
        @param filename: filename to load host keys from, or C{None}
        @type filename: str
        """
        # hostname -> keytype -> PKey
        self._keys = {}
        self.contains_hashes = False
        if filename is not None:
            self.load(filename)
    
    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        C{(hostname, keytype)} pair will be replaced.
        
        @param hostname:
        @type hostname: str
        @param keytype: key type (C{"ssh-rsa"} or C{"ssh-dss"})
        @type keytype: str
        @param key: the key to add
        @type key: L{PKey}
        """
        if not hostname in self._keys:
            self._keys[hostname] = {}
        if hostname.startswith('|1|'):
            self.contains_hashes = True
        self._keys[hostname][keytype] = key
            
    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by openssh.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        C{os.path.expanduser("~/.ssh/known_hosts")}.
        
        @param filename: name of the file to read host keys from
        @type filename: str
        """
        f = file(filename, 'r')
        for line in f:
            line = line.strip()
            if (len(line) == 0) or (line[0] == '#'):
                continue
            keylist = line.split(' ')
            if len(keylist) != 3:
                # don't understand this line
                continue
            hostlist, keytype, key = keylist
            for host in hostlist.split(','):
                if keytype == 'ssh-rsa':
                    self.add(host, keytype, RSAKey(data=base64.decodestring(key)))
                elif keytype == 'ssh-dss':
                    self.add(host, keytype, DSSKey(data=base64.decodestring(key)))
        f.close()

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        C{None} is returned.  Otherwise a dictionary of keytype to key is
        returned.
        
        @param hostname: the hostname to lookup
        @type hostname: str
        @return: keys associated with this host (or C{None})
        @rtype: dict(str, L{PKey})
        """
        if hostname in self._keys:
            return self._keys[hostname]
        if not self.contains_hashes:
            return None
        for h in self._keys.keys():
            if h.startswith('|1|'):
                hmac = self.hash_host(hostname, h)
                if hmac == h:
                    return self._keys[h]
        return None
    
    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.
        
        @param hostname: hostname (or IP) of the SSH server
        @type hostname: str
        @param key: the key to check
        @type key: L{PKey}
        @return: C{True} if the key is associated with the hostname; C{False}
            if not
        @rtype: bool
        """
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return str(host_key) == str(key)

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._keys = {}
        self.contains_hashes = False
    
    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret
    
    def keys(self):
        return self._keys.keys()

    def values(self):
        return self._keys.values();

    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by openssh when storing
        hashed hostnames in the known_hosts file.
        
        @param hostname: the hostname to hash
        @type hostname: str
        @param salt: optional salt to use when hashing (must be 20 bytes long)
        @type salt: str
        @return: the hashed hostname
        @rtype: str
        """
        if salt is None:
            salt = randpool.get_bytes(SHA.digest_size)
        else:
            if salt.startswith('|1|'):
                salt = salt.split('|')[2]
            salt = base64.decodestring(salt)
        assert len(salt) == SHA.digest_size
        hmac = HMAC.HMAC(salt, hostname, SHA).digest()
        hostkey = '|1|%s|%s' % (base64.encodestring(salt), base64.encodestring(hmac))
        return hostkey.replace('\n', '')
    hash_host = staticmethod(hash_host)

