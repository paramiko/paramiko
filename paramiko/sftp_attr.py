#!/usr/bin/python

# Copyright (C) 2003-2004 Robey Pointer <robey@lag.net>
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

import stat, time
from common import *
from sftp import *


class SFTPAttributes (object):
    """
    Representation of the attributes of a file (or proxied file) for SFTP in
    client or server mode.  It attemps to mirror the object returned by
    C{os.stat} as closely as possible, so it may have the following fields,
    with the same meanings as those returned by an C{os.stat} object:
        - st_size
        - st_uid
        - st_gid
        - st_mode
        - st_atime
        - st_mtime

    Because SFTP allows flags to have other arbitrary named attributes, these
    are stored in a dict named C{attr}.  Occasionally, the filename is also
    stored, in C{filename}.
    """
    
    FLAG_SIZE = 1
    FLAG_UIDGID = 2
    FLAG_PERMISSIONS = 4
    FLAG_AMTIME = 8
    FLAG_EXTENDED = 0x80000000L

    def __init__(self):
        """
        Create a new (empty) SFTPAttributes object.  All fields will be empty.
        """
        self._flags = 0
        self.attr = {}

    def from_stat(cls, obj):
        """
        Create an SFTPAttributes object from an existing C{stat} object (an
        object returned by C{os.stat}).

        @param obj: an object returned by C{os.stat} (or equivalent).
        @type obj: object
        @return: new L{SFTPAttributes} object with the same attribute fields.
        @rtype: L{SFTPAttributes}
        """
        attr = cls()
        attr.st_size = obj.st_size
        attr.st_uid = obj.st_uid
        attr.st_gid = obj.st_gid
        attr.st_mode = obj.st_mode
        attr.st_atime = obj.st_atime
        attr.st_mtime = obj.st_mtime
        return attr
    from_stat = classmethod(from_stat)


    ###  internals...

    
    def _from_msg(cls, msg):
        attr = cls()
        attr._unpack(msg)
        return attr
    _from_msg = classmethod(_from_msg)

    def _unpack(self, msg):
        self._flags = msg.get_int()
        if self._flags & self.FLAG_SIZE:
            self.st_size = msg.get_int64()
        if self._flags & self.FLAG_UIDGID:
            self.st_uid = msg.get_int()
            self.st_gid = msg.get_int()
        if self._flags & self.FLAG_PERMISSIONS:
            self.st_mode = msg.get_int()
        if self._flags & self.FLAG_AMTIME:
            self.st_atime = msg.get_int()
            self.st_mtime = msg.get_int()
        if self._flags & self.FLAG_EXTENDED:
            count = msg.get_int()
            for i in range(count):
                self.attr[msg.get_string()] = msg.get_string()
        return msg.get_remainder()

    def _pack(self, msg):
        self._flags = 0
        if hasattr(self, 'st_size'):
            self._flags |= self.FLAG_SIZE
        if hasattr(self, 'st_uid') or hasattr(self, 'st_gid'):
            self._flags |= self.FLAG_UIDGID
        if hasattr(self, 'st_mode'):
            self._flags |= self.FLAG_PERMISSIONS
        if hasattr(self, 'st_atime') or hasattr(self, 'st_mtime'):
            self._flags |= self.FLAG_AMTIME
        if len(self.attr) > 0:
            self._flags |= self.FLAG_EXTENDED
        msg.add_int(self._flags)
        if self._flags & self.FLAG_SIZE:
            msg.add_int64(self.st_size)
        if self._flags & self.FLAG_UIDGID:
            msg.add_int(getattr(self, 'st_uid', 0))
            msg.add_int(getattr(self, 'st_gid', 0))
        if self._flags & self.FLAG_PERMISSIONS:
            msg.add_int(self.st_mode)
        if self._flags & self.FLAG_AMTIME:
            msg.add_int(getattr(self, 'st_atime', 0))
            msg.add_int(getattr(self, 'st_mtime', 0))
        if self._flags & self.FLAG_EXTENDED:
            msg.add_int(len(self.attr))
            for key, val in self.attr.iteritems():
                msg.add_string(key)
                msg.add_string(val)
        return

    def _rwx(n, suid, sticky=False):
        if suid:
            suid = 2
        out = '-r'[n >> 2] + '-w'[(n >> 1) & 1]
        if sticky:
            out += '-xTt'[suid + (n & 1)]
        else:
            out += '-xSs'[suid + (n & 1)]
        return out
    _rwx = staticmethod(_rwx)

    def __str__(self):
        "create a unix-style long description of the file (like ls -l)"
        if hasattr(self, 'permissions'):
            kind = self.permissions & stat.S_IFMT
            if kind == stat.S_IFIFO:
                ks = 'p'
            elif kind == stat.S_IFCHR:
                ks = 'c'
            elif kind == stat.S_IFDIR:
                ks = 'd'
            elif kind == stat.S_IFBLK:
                ks = 'b'
            elif kind == stat.S_IFREG:
                ks = '-'
            elif kind == stat.S_IFLNK:
                ks = 'l'
            elif kind == stat.S_IFSOCK:
                ks = 's'
            else:
                ks = '?'
            ks += _rwx((self.permissions & 0700) >> 6, self.permissions & stat.S_ISUID)
            ks += _rwx((self.permissions & 070) >> 3, self.permissions & stat.S_ISGID)
            ks += _rwx(self.permissions & 7, self.permissions & stat.S_ISVTX, True)
        else:
            ks = '?---------'
        uid = getattr(self, 'uid', -1)
        gid = getattr(self, 'gid', -1)
        size = getattr(self, 'size', -1)
        mtime = getattr(self, 'mtime', 0)
        # compute display date
        if abs(time.time() - mtime) > 15552000:
            # (15552000 = 6 months)
            datestr = time.strftime('%d %b %Y', time.localtime(mtime))
        else:
            datestr = time.strftime('%d %b %H:%M', time.localtime(mtime))
        filename = getattr(self, 'filename', '?')
        return '%s   1 %-8d %-8d %8d %-12s %s' % (ks, uid, gid, size, datestr, filename)
