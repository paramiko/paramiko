#!/usr/bin/python

# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
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
Server-mode SFTP support.
"""

import os, errno
from common import *
from server import SubsystemHandler
from sftp import *
from sftp_si import *
from sftp_attr import *


class SFTPServer (BaseSFTP, SubsystemHandler):
    """
    Server-side SFTP subsystem support.  Since this is a L{SubsystemHandler},
    it can be (and is meant to be) set as the handler for C{"sftp"} requests.
    Use L{Transport.set_subsystem_handler} to activate this class.
    """

    def __init__(self, channel, name, server=SFTPServerInterface, server_args=None):
        """
        The constructor for SFTPServer is meant to be called from within the
        L{Transport} as a subsystem handler.  The C{server} and C{server_args}
        parameters are passed from the original call to
        L{Transport.set_subsystem_handler}.

        @param channel: channel passed from the L{Transport}.
        @type channel: L{Channel}
        @param name: name of the requested subsystem.
        @type name: str
        @param server: a subclass of L{SFTPServerInterface} to use for handling
        individual requests.
        @type server: class
        @param server_args: keyword parameters to pass to C{server} when it's
        constructed.
        @type server_args: dict
        """        
        BaseSFTP.__init__(self)
        SubsystemHandler.__init__(self, channel, name)
        transport = channel.get_transport()
        self.logger = util.get_logger(transport.get_log_channel() + '.' +
                                        channel.get_name() + '.sftp')
        self.ultra_debug = transport.ultra_debug
        self.next_handle = 1
        # map of handle-string to SFTPHandle for files & folders:
        self.file_table = { }
        self.folder_table = { }
        if server_args is None:
            server_args = {}
        self.server = server(**server_args)

    def start_subsystem(self, name, transport, channel):
        self.sock = channel
        self._log(DEBUG, 'Started sftp server on channel %s' % repr(channel))
        self._send_server_version()
        self.server.session_started()
        while True:
            try:
                t, data = self._read_packet()
            except EOFError:
                self._log(DEBUG, 'EOF -- end of session')
                return
            except Exception, e:
                self._log(DEBUG, 'Exception on channel: ' + str(e))
                self._log(DEBUG, util.tb_strings())
                return
            msg = Message(data)
            request_number = msg.get_int()
            self._process(t, request_number, msg)

    def finish_subsystem(self):
        self.server.session_ended()
        # close any file handles that were left open (so we can return them to the OS quickly)
        for f in self.file_table.itervalues():
            f.close()
        for f in self.folder_table.itervalues():
            f.close()
        self.file_table = {}
        self.folder_table = {}

    def convert_errno(e):
        """
        Convert an errno value (as from an C{OSError} or C{IOError} into a
        standard SFTP result code.  This is a convenience function for trapping
        exceptions in server code and returning an appropriate result.

        @param e: an errno code, as from C{OSError.errno}.
        @type e: int
        @return: an SFTP error code like L{SFTP_NO_SUCH_FILE}.
        @rtype: int
        """
        if e == errno.EACCES:
            # permission denied
            return SFTP_PERMISSION_DENIED
        elif e == errno.ENOENT:
            # no such file
            return SFTP_NO_SUCH_FILE
        else:
            return SFTP_FAILURE
    convert_errno = staticmethod(convert_errno)

    def set_file_attr(filename, attr):
        """
        Change a file's attributes on the local filesystem.  The contents of
        C{attr} are used to change the permissions, owner, group ownership,
        and/or modification & access time of the file, depending on which
        attributes are present in C{attr}.

        This is meant to be a handy helper function for translating SFTP file
        requests into local file operations.
        
        @param filename: name of the file to alter (should usually be an
            absolute path).
        @type filename: str
        @param attr: attributes to change.
        @type attr: L{SFTPAttributes}
        """
        if attr._flags & attr.FLAG_PERMISSIONS:
            os.chmod(filename, attr.st_mode)
        if attr._flags & attr.FLAG_UIDGID:
            os.chown(filename, attr.st_uid, attr.st_gid)
        if attr._flags & attr.FLAG_AMTIME:
            os.utime(filename, (attr.st_atime, attr.st_mtime))
    set_file_attr = staticmethod(set_file_attr)


    ###  internals...


    def _response(self, request_number, t, *arg):
        msg = Message()
        msg.add_int(request_number)
        for item in arg:
            if type(item) is int:
                msg.add_int(item)
            elif type(item) is long:
                msg.add_int64(item)
            elif type(item) is str:
                msg.add_string(item)
            elif type(item) is SFTPAttributes:
                item._pack(msg)
            else:
                raise Exception('unknown type for ' + repr(item) + ' type ' + repr(type(item)))
        self._send_packet(t, str(msg))

    def _send_handle_response(self, request_number, handle, folder=False):
        if not issubclass(type(handle), SFTPHandle):
            # must be error code
            self._send_status(request_number, handle)
            return
        handle._set_name('hx%d' % self.next_handle)
        self.next_handle += 1
        if folder:
            self.folder_table[handle._get_name()] = handle
        else:
            self.file_table[handle._get_name()] = handle
        self._response(request_number, CMD_HANDLE, handle._get_name())

    def _send_status(self, request_number, code, desc=None):
        if desc is None:
            desc = SFTP_DESC[code]
        self._response(request_number, CMD_STATUS, code, desc)

    def _open_folder(self, request_number, path):
        resp = self.server.list_folder(path)
        if issubclass(type(resp), list):
            # got an actual list of filenames in the folder
            folder = SFTPHandle()
            folder._set_files(resp)
            self._send_handle_response(request_number, folder, True)
            return
        # must be an error code
        self._send_status(request_number, resp)

    def _read_folder(self, request_number, folder):
        flist = folder._get_next_files()
        if len(flist) == 0:
            self._send_status(request_number, SFTP_EOF)
            return
        msg = Message()
        msg.add_int(request_number)
        msg.add_int(len(flist))
        for attr in flist:
            msg.add_string(attr.filename)
            msg.add_string(str(attr))
            attr._pack(msg)
        self._send_packet(CMD_NAME, str(msg))

    def _convert_pflags(self, pflags):
        "convert SFTP-style open() flags to python's os.open() flags"
        if (pflags & SFTP_FLAG_READ) and (pflags & SFTP_FLAG_WRITE):
            flags = os.O_RDWR
        elif pflags & SFTP_FLAG_WRITE:
            flags = os.O_WRONLY
        else:
            flags = os.O_RDONLY
        if pflags & SFTP_FLAG_APPEND:
            flags |= os.O_APPEND
        if pflags & SFTP_FLAG_CREATE:
            flags |= os.O_CREAT
        if pflags & SFTP_FLAG_TRUNC:
            flags |= os.O_TRUNC
        if pflags & SFTP_FLAG_EXCL:
            flags |= os.O_EXCL
        return flags

    def _process(self, t, request_number, msg):
        self._log(DEBUG, 'Request: %s' % CMD_NAMES[t])
        if t == CMD_OPEN:
            path = msg.get_string()
            flags = self._convert_pflags(msg.get_int())
            attr = SFTPAttributes._from_msg(msg)
            self._send_handle_response(request_number, self.server.open(path, flags, attr))
        elif t == CMD_CLOSE:
            handle = msg.get_string()
            if self.folder_table.has_key(handle):
                del self.folder_table[handle]
                self._send_status(request_number, SFTP_OK)
                return
            if self.file_table.has_key(handle):
                self.file_table[handle].close()
                del self.file_table[handle]
                self._send_status(request_number, SFTP_OK)
                return
            self._send_status(request_number, SFTP_BAD_MESSAGE, 'Invalid handle')
        elif t == CMD_READ:
            handle = msg.get_string()
            offset = msg.get_int64()
            length = msg.get_int()
            if not self.file_table.has_key(handle):
                self._send_status(request_number, SFTP_BAD_MESSAGE, 'Invalid handle')
                return
            data = self.file_table[handle].read(offset, length)
            if type(data) is str:
                if len(data) == 0:
                    self._send_status(request_number, SFTP_EOF)
                else:
                    self._response(request_number, CMD_DATA, data)
            else:
                self._send_status(request_number, data)
        elif t == CMD_WRITE:
            handle = msg.get_string()
            offset = msg.get_int64()
            data = msg.get_string()
            if not self.file_table.has_key(handle):
                self._send_status(request_number, SFTP_BAD_MESSAGE, 'Invalid handle')
                return
            self._send_status(request_number, self.file_table[handle].write(offset, data))
        elif t == CMD_REMOVE:
            path = msg.get_string()
            self._send_status(request_number, self.server.remove(path))
        elif t == CMD_RENAME:
            oldpath = msg.get_string()
            newpath = msg.get_string()
            self._send_status(request_number, self.server.rename(oldpath, newpath))
        elif t == CMD_MKDIR:
            path = msg.get_string()
            attr = SFTPAttributes._from_msg(msg)
            self._send_status(request_number, self.server.mkdir(path, attr))
        elif t == CMD_RMDIR:
            path = msg.get_string()
            self._send_status(request_number, self.server.rmdir(path))
        elif t == CMD_OPENDIR:
            path = msg.get_string()
            self._open_folder(request_number, path)
            return
        elif t == CMD_READDIR:
            handle = msg.get_string()
            if not self.folder_table.has_key(handle):
                self._send_status(request_number, SFTP_BAD_MESSAGE, 'Invalid handle')
                return
            folder = self.folder_table[handle]
            self._read_folder(request_number, folder)
        elif t == CMD_STAT:
            path = msg.get_string()
            resp = self.server.stat(path)
            if issubclass(type(resp), SFTPAttributes):
                self._response(request_number, CMD_ATTRS, resp)
            else:
                self._send_status(request_number, resp)
        elif t == CMD_LSTAT:
            path = msg.get_string()
            resp = self.server.lstat(path)
            if issubclass(type(resp), SFTPAttributes):
                self._response(request_number, CMD_ATTRS, resp)
            else:
                self._send_status(request_number, resp)
        elif t == CMD_FSTAT:
            handle = msg.get_string()
            if not self.file_table.has_key(handle):
                self._send_status(request_number, SFTP_BAD_MESSAGE, 'Invalid handle')
                return
            resp = self.file_table[handle].stat()
            if issubclass(type(resp), SFTPAttributes):
                self._response(request_number, CMD_ATTRS, resp)
            else:
                self._send_status(request_number, resp)
        elif t == CMD_SETSTAT:
            path = msg.get_string()
            attr = SFTPAttributes._from_msg(msg)
            self._send_status(request_number, self.server.chattr(path, attr))
        elif t == CMD_FSETSTAT:
            handle = msg.get_string()
            attr = SFTPAttributes._from_msg(msg)
            if not self.file_table.has_key(handle):
                self._response(request_number, SFTP_BAD_MESSAGE, 'Invalid handle')
                return
            self._send_status(request_number, self.file_table[handle].chattr(attr))
        elif t == CMD_READLINK:
            path = msg.get_string()
            resp = self.server.readlink(path)
            if type(resp) is str:
                self._response(request_number, CMD_NAME, 1, resp, '', SFTPAttributes())
            else:
                self._send_status(request_number, resp)
        elif t == CMD_SYMLINK:
            # the sftp 2 draft is incorrect here!  path always follows target_path
            target_path = msg.get_string()
            path = msg.get_string()
            self._send_status(request_number, self.server.symlink(target_path, path))
        elif t == CMD_REALPATH:
            path = msg.get_string()
            rpath = self.server.canonicalize(path)
            self._response(request_number, CMD_NAME, 1, rpath, '', SFTPAttributes())
        else:
            self._send_status(request_number, SFTP_OP_UNSUPPORTED)


from sftp_handle import SFTPHandle
