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

import struct, socket
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

FXF_READ = 0x1
FXF_WRITE = 0x2
FXF_APPEND = 0x4
FXF_CREATE = 0x8
FXF_TRUNC = 0x10
FXF_EXCL = 0x20

_VERSION = 3


class SFTPAttributes (object):

    FLAG_SIZE = 1
    FLAG_UIDGID = 2
    FLAG_PERMISSIONS = 4
    FLAG_AMTIME = 8
    FLAG_EXTENDED = 0x80000000L

    def __init__(self, msg=None):
        self.flags = 0
        self.attr = {}
        if msg is not None:
            self.unpack(msg)

    def unpack(self, msg):
        self.flags = msg.get_int()
        if self.flags & self.FLAG_SIZE:
            self.size = msg.get_int64()
        if self.flags & self.FLAG_UIDGID:
            self.uid = msg.get_int()
            self.gid = msg.get_int()
        if self.flags & self.FLAG_PERMISSIONS:
            self.permissions = msg.get_int()
        if self.flags & self.FLAG_AMTIME:
            self.atime = msg.get_int()
            self.mtime = msg.get_int()
        if self.flags & self.FLAG_EXTENDED:
            count = msg.get_int()
            for i in range(count):
                self.attr[msg.get_string()] = msg.get_string()
        return msg.get_remainder()

    def pack(self, msg):
        self.flags = 0
        if hasattr(self, 'size'):
            self.flags |= self.FLAG_SIZE
        if hasattr(self, 'uid') or hasattr(self, 'gid'):
            self.flags |= self.FLAG_UIDGID
        if hasattr(self, 'permissions'):
            self.flags |= self.FLAG_PERMISSIONS
        if hasattr(self, 'atime') or hasattr(self, 'mtime'):
            self.flags |= self.FLAG_AMTIME
        if len(self.attr) > 0:
            self.flags |= self.FLAG_EXTENDED
        msg.add_int(self.flags)
        if self.flags & self.FLAG_SIZE:
            msg.add_int64(self.size)
        if self.flags & self.FLAG_UIDGID:
            msg.add_int(getattr(self, 'uid', 0))
            msg.add_int(getattr(self, 'gid', 0))
        if self.flags & self.FLAG_PERMISSIONS:
            msg.add_int(self.permissions)
        if self.flags & self.FLAG_AMTIME:
            msg.add_int(getattr(self, 'atime', 0))
            msg.add_int(getattr(self, 'mtime', 0))
        if self.flags & self.FLAG_EXTENDED:
            msg.add_int(len(self.attr))
            for key, val in self.attr:
                msg.add_string(key)
                msg.add_string(val)
        return

    def _pythonize(self):
        "create attributes named the way python's os.stat does it"
        if hasattr(self, 'size'):
            self.st_size = self.size
        if hasattr(self, 'uid'):
            self.st_uid = self.uid
        if hasattr(self, 'gid'):
            self.st_gid = self.gid
        if hasattr(self, 'permissions'):
            self.st_mode = self.permissions
        if hasattr(self, 'atime'):
            self.st_atime = self.atime
        if hasattr(self, 'mtime'):
            self.st_mtime = self.mtime


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
        attr = SFTPAttributes()
        attr.unpack(msg)
        try:
            return attr.size
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
        attr = SFTPAttributes(msg)
        attr._pythonize()
        return attr


class BaseSFTP (object):
    def _send_version(self):
        self._send_packet(CMD_INIT, struct.pack('>I', _VERSION))
        t, data = self._read_packet()
        if t != CMD_VERSION:
            raise SFTPError('Incompatible sftp protocol')
        version = struct.unpack('>I', data[:4])[0]
        #        if version != _VERSION:
        #            raise SFTPError('Incompatible sftp protocol')
        return version


    ###  internals...


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
