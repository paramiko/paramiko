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

import struct, socket, stat, time
from common import *
import util
from channel import Channel
from message import Message
from file import BufferedFile

CMD_INIT, CMD_VERSION, CMD_OPEN, CMD_CLOSE, CMD_READ, CMD_WRITE, CMD_LSTAT, CMD_FSTAT, \
           CMD_SETSTAT, CMD_FSETSTAT, CMD_OPENDIR, CMD_READDIR, CMD_REMOVE, CMD_MKDIR, \
           CMD_RMDIR, CMD_REALPATH, CMD_STAT, CMD_RENAME, CMD_READLINK, CMD_SYMLINK \
           = range(1, 21)
CMD_STATUS, CMD_HANDLE, CMD_DATA, CMD_NAME, CMD_ATTRS = range(101, 106)
CMD_EXTENDED, CMD_EXTENDED_REPLY = range(200, 202)

FX_OK = 0
FX_EOF, FX_NO_SUCH_FILE, FX_PERMISSION_DENIED, FX_FAILURE, FX_BAD_MESSAGE, \
         FX_NO_CONNECTION, FX_CONNECTION_LOST, FX_OP_UNSUPPORTED = range(1, 9)

FX_DESC = [ 'Success',
            'End of file',
            'No such file',
            'Permission denied',
            'Failure',
            'Bad message',
            'No connection',
            'Connection lost',
            'Operation unsupported' ]

FXF_READ = 0x1
FXF_WRITE = 0x2
FXF_APPEND = 0x4
FXF_CREATE = 0x8
FXF_TRUNC = 0x10
FXF_EXCL = 0x20

_VERSION = 3


class SFTPAttributes (object):
    """
    Representation of the attributes of a file (or proxied file) for SFTP in
    client or server mode.  It attemps to mirror the object returned by
    C{os.stat} as closely as possible, so it may have the following fields:
        - st_size
        - st_uid
        - st_gid
        - st_mode
        - st_atime
        - st_mtime

    Because SFTP allows flags to have other arbitrary named attributes, these
    are stored in a dict named C{attr}.
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
        return '%s   1 %-8d %-8d %8d %-12s' % (ks, uid, gid, size, datestr)
                


class SFTPError (Exception):
    pass


class SFTPFile (BufferedFile):

    """
    Some sftp servers will choke if you send read/write requests larger than
    this size.
    """
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)

    def _get_size(self):
        t, msg = self.sftp._request(CMD_FSTAT, self.handle)
        if t != CMD_ATTRS:
            raise SFTPError('Expected attrs')
        attr = SFTPAttributes._from_msg(msg)
        try:
            return attr.st_size
        except:
            return 0

    def close(self):
        BufferedFile.close(self)
        self.sftp._request(CMD_CLOSE, self.handle)

    def _read(self, size):
        size = min(size, self.MAX_REQUEST_SIZE)
        t, msg = self.sftp._request(CMD_READ, self.handle, long(self._realpos), int(size))
        if t != CMD_DATA:
            raise SFTPError('Expected data')
        return msg.get_string()

    def _write(self, data):
        offset = 0
        while offset < len(data):
            chunk = min(len(data) - offset, self.MAX_REQUEST_SIZE)
            t, msg = self.sftp._request(CMD_WRITE, self.handle, long(self._realpos + offset),
                                        str(data[offset : offset + chunk]))
            offset += chunk
        return len(data)

    def settimeout(self, timeout):
        """
        Set a timeout on read/write operations on the underlying socket or
        ssh L{Channel}.

        @see: L{Channel.settimeout}
        @param timeout: seconds to wait for a pending read/write operation
        before raising C{socket.timeout}, or C{None} for no timeout
        @type timeout: float
        """
        self.sock.settimeout(timeout)

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a float) associated with the socket
        or ssh L{Channel} used for this file.

        @see: L{Channel.gettimeout}
        @rtype: float
        """
        return self.sock.gettimeout()

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode on the underiying socket or ssh
        L{Channel}.

        @see: L{Channel.setblocking}
        @param blocking: 0 to set non-blocking mode; non-0 to set blocking
        mode.
        @type blocking: int
        """
        self.sock.setblocking(blocking)

    def seek(self, offset, whence=0):
        self.flush()
        if whence == self.SEEK_SET:
            self._realpos = self._pos = offset
        elif whence == self.SEEK_CUR:
            self._realpos += offset
            self._pos += offset
        else:
            self._realpos = self._pos = self._get_size() + offset
        self._rbuffer = ''

    def stat(self):
        """
        Retrieve information about this file from the remote system.  This is
        exactly like L{SFTP.stat}, except that it operates on an already-open
        file.

        @return: an object containing attributes about this file.
        @rtype: SFTPAttributes
        """
        t, msg = self.sftp._request(CMD_FSTAT, self.handle)
        if t != CMD_ATTRS:
            raise SFTPError('Expected attributes')
        return SFTPAttributes._from_msg(msg)


class BaseSFTP (object):
    def __init__(self):
        self.logger = logging.getLogger('paramiko.sftp')


    ###  internals...


    def _send_version(self):
        self._send_packet(CMD_INIT, struct.pack('>I', _VERSION))
        t, data = self._read_packet()
        if t != CMD_VERSION:
            raise SFTPError('Incompatible sftp protocol')
        version = struct.unpack('>I', data[:4])[0]
        #        if version != _VERSION:
        #            raise SFTPError('Incompatible sftp protocol')
        return version

    def _send_server_version(self):
        self._send_packet(CMD_VERSION, struct.pack('>I', _VERSION))
        t, data = self._read_packet()
        if t != CMD_INIT:
            raise SFTPError('Incompatible sftp protocol')
        version = struct.unpack('>I', data[:4])[0]
        return version
        
    def _log(self, level, msg):
        if type(msg) == type([]):
            for m in msg:
                self.logger.log(level, m)
        else:
            self.logger.log(level, msg)

    def _write_all(self, out):
        while len(out) > 0:
            n = self.sock.send(out)
            if n <= 0:
                raise EOFError()
            if n == len(out):
                return
            out = out[n:]
        return

    def _read_all(self, n):
        out = ''
        while n > 0:
            x = self.sock.recv(n)
            if len(x) == 0:
                raise EOFError()
            out += x
            n -= len(x)
        return out

    def _send_packet(self, t, packet):
        out = struct.pack('>I', len(packet) + 1) + chr(t) + packet
        if self.ultra_debug:
            self._log(DEBUG, util.format_binary(out, 'OUT: '))
        self._write_all(out)

    def _read_packet(self):
        size = struct.unpack('>I', self._read_all(4))[0]
        data = self._read_all(size)
        if self.ultra_debug:
            self._log(DEBUG, util.format_binary(data, 'IN: '));
        if size > 0:
            return ord(data[0]), data[1:]
        return 0, ''
