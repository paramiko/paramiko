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

_CMD_INIT, _CMD_VERSION, _CMD_OPEN, _CMD_CLOSE, _CMD_READ, _CMD_WRITE, _CMD_LSTAT, _CMD_FSTAT, \
           _CMD_SETSTAT, _CMD_FSETSTAT, _CMD_OPENDIR, _CMD_READDIR, _CMD_REMOVE, _CMD_MKDIR, \
           _CMD_RMDIR, _CMD_REALPATH, _CMD_STAT, _CMD_RENAME, _CMD_READLINK, _CMD_SYMLINK \
           = range(1, 21)
_CMD_STATUS, _CMD_HANDLE, _CMD_DATA, _CMD_NAME, _CMD_ATTRS = range(101, 106)
_CMD_EXTENDED, _CMD_EXTENDED_REPLY = range(200, 202)

_FX_OK = 0
_FX_EOF, _FX_NO_SUCH_FILE, _FX_PERMISSION_DENIED, _FX_FAILURE, _FX_BAD_MESSAGE, \
         _FX_NO_CONNECTION, _FX_CONNECTION_LOST, _FX_OP_UNSUPPORTED = range(1, 9)

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

    # some sftp servers will choke if you send read/write requests larger than
    # this size.
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)

    def _get_size(self):
        t, msg = self.sftp._request(_CMD_FSTAT, self.handle)
        if t != _CMD_ATTRS:
            raise SFTPError('Expected attrs')
        attr = SFTPAttributes()
        attr.unpack(msg)
        try:
            return attr.size
        except:
            return 0

    def close(self):
        BufferedFile.close(self)
        self.sftp._request(_CMD_CLOSE, self.handle)

    def _read(self, size):
        size = min(size, self.MAX_REQUEST_SIZE)
        t, msg = self.sftp._request(_CMD_READ, self.handle, long(self._realpos), int(size))
        if t != _CMD_DATA:
            raise SFTPError('Expected data')
        return msg.get_string()

    def _write(self, data):
        offset = 0
        while offset < len(data):
            chunk = min(len(data) - offset, self.MAX_REQUEST_SIZE)
            t, msg = self.sftp._request(_CMD_WRITE, self.handle, long(self._realpos + offset),
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
        t, msg = self.sftp._request(_CMD_FSTAT, self.handle)
        if t != _CMD_ATTRS:
            raise SFTPError('Expected attributes')
        attr = SFTPAttributes(msg)
        attr._pythonize()
        return attr


class SFTP (object):
    def __init__(self, sock):
        self.sock = sock
        self.ultra_debug = False
        self.request_number = 1
        if type(sock) is Channel:
            self.logger = logging.getLogger('paramiko.chan.' + sock.get_name() + '.sftp')
        else:
            self.logger = logging.getLogger('paramiko.sftp')
        # protocol:  (maybe should move to a different method)
        self._send_packet(_CMD_INIT, struct.pack('>I', VERSION))
        t, data = self._read_packet()
        if t != _CMD_VERSION:
            raise SFTPError('Incompatible sftp protocol')
        version = struct.unpack('>I', data[:4])[0]
#        if version != VERSION:
#            raise SFTPError('Incompatible sftp protocol')

    def from_transport(selfclass, t):
        chan = t.open_session()
        if chan is None:
            return None
        chan.invoke_subsystem('sftp')
        return selfclass(chan)
    from_transport = classmethod(from_transport)

    def listdir(self, path):
        """
        Return a list containing the names of the entries in the given C{path}.
        The list is in arbitrary order.  It does not include the special
        entries C{'.'} and C{'..'} even if they are present in the folder.

        @param path: path to list.
        @type path: string
        @return: list of filenames.
        @rtype: list of string
        """
        t, msg = self._request(_CMD_OPENDIR, path)
        if t != _CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_string()
        filelist = []
        while 1:
            try:
                t, msg = self._request(_CMD_READDIR, handle)
            except EOFError, e:
                # done with handle
                break
            if t != _CMD_NAME:
                raise SFTPError('Expected name response')
            count = msg.get_int()
            for i in range(count):
                filename = msg.get_string()
                longname = msg.get_string()
                attr = SFTPAttributes(msg)
                if (filename != '.') and (filename != '..'):
                    filelist.append(filename)
                # currently we ignore the rest
        self._request(_CMD_CLOSE, handle)
        return filelist

    def open(self, filename, mode='r', bufsize=-1):
        """
        Open a file on the remote server.  The arguments are the same as for
        python's built-in C{open} (aka C{file}).  A file-like object is
        returned, which closely mimics the behavior of a normal python file
        object.

        The mode indicates how the file is to be opened: C{'r'} for reading,
        C{'w'} for writing (truncating an existing file), C{'a'} for appending,
        C{'r+'} for reading/writing, C{'w+'} for reading/writing (truncating an
        existing file), C{'a+'} for reading/appending.  The python C{'b'} flag
        is ignored, since SSH treats all files as binary.  The C{'U'} flag is
        supported in a compatible way.

        @param filename: name of the file to open.
        @type filename: string
        @param mode: mode (python-style) to open in.
        @type mode: string
        @param bufsize: desired buffering (-1 = default buffer size, 0 =
        unbuffered, 1 = line buffered, >1 = requested buffer size).
        @type bufsize: int
        @return: a file object representing the open file.
        @rtype: SFTPFile

        @raise IOError: if the file could not be opened.
        """
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
        t, msg = self._request(_CMD_OPEN, filename, imode, attrblock)
        if t != _CMD_HANDLE:
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
        self._request(_CMD_REMOVE, path)

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
        self._request(_CMD_RENAME, oldpath, newpath)

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
        self._request(_CMD_MKDIR, path, attr)

    def rmdir(self, path):
        """
        Remove the folder named C{path}.

        @param path: name of the folder to remove.
        @type path: string
        """
        self._request(_CMD_RMDIR, path)

    def stat(self, path):
        """
        Retrieve information about a file on the remote system.  The return
        value is an object whose attributes correspond to the attributes of
        python's C{stat} structure as returned by C{os.stat}, except that it
        contains fewer fields.  An SFTP server may return as much or as little
        info as it wants, so the results may vary from server to server.

        Unlike a python C{stat} object, the result may not be accessed as a
        tuple.  This is mostly due to the author's slack factor.

        The fields supported are: C{st_mode}, C{st_size}, C{st_uid}, C{st_gid},
        C{st_atime}, and C{st_mtime}.

        @param path: the filename to stat.
        @type path: string
        @return: an object containing attributes about the given file.
        @rtype: SFTPAttributes
        """
        t, msg = self._request(_CMD_STAT, path)
        if t != _CMD_ATTRS:
            raise SFTPError('Expected attributes')
        attr = SFTPAttributes(msg)
        attr._pythonize()
        return attr

    def lstat(self, path):
        """
        Retrieve information about a file on the remote system, without
        following symbolic links (shortcuts).  This otherwise behaves exactly
        the same as L{stat}.

        @param path: the filename to stat.
        @type path: string
        @return: an object containing attributes about the given file.
        @rtype: SFTPAttributes
        """
        t, msg = self._request(_CMD_LSTAT, path)
        if t != _CMD_ATTRS:
            raise SFTPError('Expected attributes')
        attr = SFTPAttributes(msg)
        attr._pythonize()
        return attr

    def symlink(self, source, dest):
        """
        Create a symbolic link (shortcut) of the C{source} path at
        C{destination}.

        @param source: path of the original file.
        @type source: string
        @param dest: path of the newly created symlink.
        @type dest: string
        """
        self._request(_CMD_SYMLINK, source, dest)

    def chmod(self, path, mode):
        """
        Change the mode (permissions) of a file.  The permissions are
        unix-style and identical to those used by python's C{os.chmod}
        function.

        @param path: path of the file to change the permissions of.
        @type path: string
        @param mode: new permissions.
        @type mode: int
        """
        attr = SFTPAttributes()
        attr.permissions = mode
        self._request(_CMD_SETSTAT, path, attr)
        
    def chown(self, path, uid, gid):
        """
        Change the owner (C{uid}) and group (C{gid}) of a file.  As with
        python's C{os.chown} function, you must pass both arguments, so if you
        only want to change one, use L{stat} first to retrieve the current
        owner and group.

        @param path: path of the file to change the owner and group of.
        @type path: string
        @param uid: new owner's uid
        @type uid: int
        @param gid: new group id
        @type gid: int
        """
        attr = SFTPAttributes()
        attr.uid, attr.gid = uid, gid
        self._request(_CMD_SETSTAT, path, attr)

    def utime(self, path, times):
        """
        Set the access and modified times of the file specified by C{path}.  If
        C{times} is C{None}, then the file's access and modified times are set
        to the current time.  Otherwise, C{times} must be a 2-tuple of numbers,
        of the form C{(atime, mtime)}, which is used to set the access and
        modified times, respectively.  This bizarre API is mimicked from python
        for the sake of consistency -- I apologize.

        @param path: path of the file to modify.
        @type path: string
        @param times: C{None} or a tuple of (access time, modified time) in
        standard internet epoch time (seconds since 01 January 1970 GMT).
        @type times: tuple of int
        """
        if times is None:
            times = (time.time(), time.time())
        attr = SFTPAttributes()
        attr.atime, attr.mtime = times
        self._request(_CMD_SETSTAT, path, attr)

    def readlink(self, path):
        """
        Return the target of a symbolic link (shortcut).  You can use
        L{symlink} to create these.  The result may be either an absolute or
        relative pathname.

        @param path: path of the symbolic link file.
        @type path: string
        @return: target path.
        @rtype: string
        """
        t, msg = self._request(_CMD_READLINK, path)
        if t != _CMD_NAME:
            raise SFTPError('Expected name response')
        count = msg.get_int()
        if count == 0:
            return None
        if count != 1:
            raise SFTPError('Readlink returned %d results' % count)
        return msg.get_string()


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
        if t == _CMD_STATUS:
            self._convert_status(msg)
        return t, msg

    def _convert_status(self, msg):
        """
        Raises EOFError or IOError on error status; otherwise does nothing.
        """
        code = msg.get_int()
        text = msg.get_string()
        if code == _FX_OK:
            return
        elif code == _FX_EOF:
            raise EOFError(text)
        else:
            raise IOError(text)

