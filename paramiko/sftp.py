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
# along with Foobar; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import struct, logging, socket
from util import format_binary, tb_strings
from channel import Channel
from message import Message
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
from file import BufferedFile

CMD_INIT, CMD_VERSION, CMD_OPEN, CMD_CLOSE, CMD_READ, CMD_WRITE, CMD_LSTAT, CMD_FSTAT, CMD_SETSTAT, \
          CMD_FSETSTAT, CMD_OPENDIR, CMD_READDIR, CMD_REMOVE, CMD_MKDIR, CMD_RMDIR, CMD_REALPATH, \
          CMD_STAT, CMD_RENAME, CMD_READLINK, CMD_SYMLINK = range(1, 21)
CMD_STATUS, CMD_HANDLE, CMD_DATA, CMD_NAME, CMD_ATTRS = range(101, 106)
CMD_EXTENDED, CMD_EXTENDED_REPLY = range(200, 202)

FX_OK = 0
FX_EOF, FX_NO_SUCH_FILE, FX_PERMISSION_DENIED, FX_FAILURE, FX_BAD_MESSAGE, FX_NO_CONNECTION, \
        FX_CONNECTION_LOST, FX_OP_UNSUPPORTED = range(1, 9)

VERSION = 3


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

        
class SFTPError (Exception):
    pass


class SFTPFile (BufferedFile):
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
        t, msg = self.sftp._request(CMD_READ, self.handle, long(self._realpos), int(size))
        if t != CMD_DATA:
            raise SFTPError('Expected data')
        return msg.get_string()

    def _write(self, data):
        t, msg = self.sftp._request(CMD_WRITE, self.handle, long(self._realpos), str(data))
        return len(data)

    def seek(self, offset, whence=0):
        if whence == self.SEEK_SET:
            self._realpos = self._pos = offset
        elif whence == self.SEEK_CUR:
            self._realpos += offset
            self._pos += offset
        else:
            self._realpos = self._pos = self._get_size() + offset
        self._rbuffer = self._wbuffer = ''


class SFTP (object):
    def __init__(self, sock):
        self.sock = sock
        self.ultra_debug = 1
        self.request_number = 1
        if type(sock) is Channel:
            self.logger = logging.getLogger('paramiko.chan.' + sock.get_name() + '.sftp')
        else:
            self.logger = logging.getLogger('paramiko.sftp')
        # protocol:  (maybe should move to a different method)
        self._send_packet(CMD_INIT, struct.pack('>I', VERSION))
        t, data = self._read_packet()
        if t != CMD_VERSION:
            raise SFTPError('Incompatible sftp protocol')
        version = struct.unpack('>I', data[:4])[0]
        if version != VERSION:
            raise SFTPError('Incompatible sftp protocol')

    def from_transport(selfclass, t):
        chan = t.open_session()
        if chan is None:
            return None
        chan.invoke_subsystem('sftp')
        return selfclass(chan)
    from_transport = classmethod(from_transport)

    def listdir(self, path):
        t, msg = self._request(CMD_OPENDIR, path)
        if t != CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_string()
        filelist = []
        while 1:
            try:
                t, msg = self._request(CMD_READDIR, handle)
            except EOFError, e:
                # done with handle
                break
            if t != CMD_NAME:
                raise SFTPError('Expected name response')
            count = msg.get_int()
            for i in range(count):
                filename = msg.get_string()
                longname = msg.get_string()
                attr = SFTPAttributes(msg)
                if (filename != '.') and (filename != '..'):
                    filelist.append(filename)
                # currently we ignore the rest
        self._request(CMD_CLOSE, handle)
        return filelist

    def open(self, filename, mode='r', bufsize=-1):
        imode = 0
        if ('r' in mode) or ('+' in mode):
            imode |= self._FXF_READ
        if ('w' in mode) or ('+' in mode):
            imode |= self._FXF_WRITE
        if ('w' in mode):
            imode |= self._FXF_CREATE | self._FXF_TRUNC
        if ('a' in mode):
            imode |= self._FXF_APPEND
        attrblock = SFTPAttributes()
        t, msg = self._request(CMD_OPEN, filename, imode, attrblock)
        if t != CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_string()
        return SFTPFile(self, handle, mode, bufsize)

    def remove(self, path):
        """
        Remove the file at the given path.

        @param path: path (absolute or relative) of the file to remove.
        @type path: string

        @raise IOError: if the path refers to a folder (directory).  Use
        L{rmdir} to remove a folder.
        """
        self._request(CMD_REMOVE, path)

    unlink = remove

    def rename(self, oldpath, newpath):
        """
        Rename a file or folder from C{oldpath} to C{newpath}.

        @param oldpath: existing name of the file or folder.
        @type oldpath: string
        @param newpath: new name for the file or folder.
        @type newpath: string
        
        @raise IOError: if C{newpath} is a folder, or something else goes
        wrong.
        """
        self._request(CMD_RENAME, oldpath, newpath)

    def mkdir(self, path, mode=0777):
        """
        Create a folder (directory) named C{path} with numeric mode C{mode}.
        The default mode is 0777 (octal).  On some systems, mode is ignored.
        Where it is used, the current umask value is first masked out.

        @param path: name of the folder to create.
        @type path: string
        @param mode: permissions (posix-style) for the newly-created folder.
        @type mode: int
        """
        attr = SFTPAttributes()
        attr.permissions = mode
        self._request(CMD_MKDIR, path, attr)


    ###  internals...


    _FXF_READ = 0x1
    _FXF_WRITE = 0x2
    _FXF_APPEND = 0x4
    _FXF_CREATE = 0x8
    _FXF_TRUNC = 0x10
    _FXF_EXCL = 0x20


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
            try:
                x = self.sock.recv(n)
                if len(x) == 0:
                    raise EOFError()
                out += x
                n -= len(x)
            except socket.timeout:
                if not self.active:
                    raise EOFError()
        return out

    def _send_packet(self, t, packet):
        out = struct.pack('>I', len(packet) + 1) + chr(t) + packet
        if self.ultra_debug:
            self._log(DEBUG, format_binary(out, 'OUT: '))
        self._write_all(out)

    def _read_packet(self):
        size = struct.unpack('>I', self._read_all(4))[0]
        data = self._read_all(size)
        if self.ultra_debug:
            self._log(DEBUG, format_binary(data, 'IN: '));
        if size > 0:
            return ord(data[0]), data[1:]
        return 0, ''

    def _request(self, t, *arg):
        msg = Message()
        msg.add_int(self.request_number)
        for item in arg:
            if type(item) is int:
                msg.add_int(item)
            elif type(item) is long:
                msg.add_int64(item)
            elif type(item) is str:
                msg.add_string(item)
            elif type(item) is SFTPAttributes:
                item.pack(msg)
            else:
                raise Exception('unknown type for ' + repr(item) + ' type ' + repr(type(item)))
        self._send_packet(t, str(msg))
        t, data = self._read_packet()
        msg = Message(data)
        num = msg.get_int()
        if num != self.request_number:
            raise SFTPError('Expected response #%d, got response #%d' % (self.request_number, num))
        self.request_number += 1
        if t == CMD_STATUS:
            self._convert_status(msg)
        return t, msg

    def _convert_status(self, msg):
        """
        Raises EOFError or IOError on error status; otherwise does nothing.
        """
        code = msg.get_int()
        text = msg.get_string()
        if code == FX_OK:
            return
        elif code == FX_EOF:
            raise EOFError(text)
        else:
            raise IOError(text)


