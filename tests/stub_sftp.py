# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
A stub SFTP server for loopback SFTP testing.
"""

import functools
import os

from paramiko import (
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    SFTPAttributes,
    SFTPHandle,
    SFTPServer,
    SFTPServerInterface,
    SFTP_FAILURE,
    SFTP_OK,
    ServerInterface,
)
from paramiko.common import o666


class StubServer(ServerInterface):
    def check_auth_password(self, username, password):
        # all are allowed
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


def return_errno_on_error(func):
    @functools.wraps(func)
    def wrapped_func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    return wrapped_func


class StubSFTPHandle(SFTPHandle):
    @return_errno_on_error
    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))

    @return_errno_on_error
    def chattr(self, attr):
        # python doesn't have equivalents to fchown or fchmod, so we have to
        # use the stored filename
        SFTPServer.set_file_attr(self.filename, attr)
        return SFTP_OK


class StubSFTPServer(SFTPServerInterface):
    # assume current folder is a fine root
    # (the tests always create and eventually delete a subfolder, so there
    # shouldn't be any mess)
    ROOT = os.getcwd()

    def _realpath(self, path):
        return self.ROOT + self.canonicalize(path)

    @return_errno_on_error
    def list_folder(self, path):
        path = self._realpath(path)
        out = []
        flist = os.listdir(path)
        for fname in flist:
            attr = SFTPAttributes.from_stat(os.stat(os.path.join(path, fname)))
            attr.filename = fname
            out.append(attr)
        return out

    @return_errno_on_error
    def stat(self, path):
        path = self._realpath(path)
        return SFTPAttributes.from_stat(os.stat(path))

    @return_errno_on_error
    def lstat(self, path):
        path = self._realpath(path)
        return SFTPAttributes.from_stat(os.lstat(path))

    @return_errno_on_error
    def open(self, path, flags, attr):
        path = self._realpath(path)
        binary_flag = getattr(os, "O_BINARY", 0)
        flags |= binary_flag
        mode = getattr(attr, "st_mode", None)
        if mode is not None:
            fd = os.open(path, flags, mode)
        else:
            # os.open() defaults to 0777 which is
            # an odd default mode for files
            fd = os.open(path, flags, o666)
        if (flags & os.O_CREAT) and (attr is not None):
            attr._flags &= ~attr.FLAG_PERMISSIONS
            SFTPServer.set_file_attr(path, attr)
        if flags & os.O_WRONLY:
            if flags & os.O_APPEND:
                fstr = "ab"
            else:
                fstr = "wb"
        elif flags & os.O_RDWR:
            if flags & os.O_APPEND:
                fstr = "a+b"
            else:
                fstr = "r+b"
        else:
            # O_RDONLY (== 0)
            fstr = "rb"
        f = os.fdopen(fd, fstr)
        fobj = StubSFTPHandle(flags)
        fobj.filename = path
        fobj.readfile = f
        fobj.writefile = f
        return fobj

    @return_errno_on_error
    def remove(self, path):
        path = self._realpath(path)
        os.remove(path)
        return SFTP_OK

    @return_errno_on_error
    def rename(self, oldpath, newpath):
        oldpath = self._realpath(oldpath)
        newpath = self._realpath(newpath)
        if os.path.exists(newpath):
            return SFTP_FAILURE
        os.rename(oldpath, newpath)
        return SFTP_OK

    @return_errno_on_error
    def posix_rename(self, oldpath, newpath):
        oldpath = self._realpath(oldpath)
        newpath = self._realpath(newpath)
        os.rename(oldpath, newpath)
        return SFTP_OK

    @return_errno_on_error
    def mkdir(self, path, attr):
        path = self._realpath(path)
        os.mkdir(path)
        if attr is not None:
            SFTPServer.set_file_attr(path, attr)
        return SFTP_OK

    @return_errno_on_error
    def rmdir(self, path):
        path = self._realpath(path)
        os.rmdir(path)
        return SFTP_OK

    @return_errno_on_error
    def chattr(self, path, attr):
        path = self._realpath(path)
        SFTPServer.set_file_attr(path, attr)
        return SFTP_OK

    @return_errno_on_error
    def symlink(self, target_path, path):
        path = self._realpath(path)
        if (len(target_path) > 0) and (target_path[0] == "/"):
            # absolute symlink
            target_path = os.path.join(self.ROOT, target_path[1:])
            if target_path[:2] == "//":
                # bug in os.path.join
                target_path = target_path[1:]
        else:
            # compute relative to path
            abspath = os.path.join(os.path.dirname(path), target_path)
            if abspath[: len(self.ROOT)] != self.ROOT:
                # this symlink isn't going to work anyway -- just break it
                # immediately
                target_path = "<error>"
        os.symlink(target_path, path)
        return SFTP_OK

    @return_errno_on_error
    def readlink(self, path):
        path = self._realpath(path)
        symlink = os.readlink(path)
        # if it's absolute, remove the root
        if os.path.isabs(symlink):
            if symlink[: len(self.ROOT)] == self.ROOT:
                symlink = symlink[len(self.ROOT) :]
                if (len(symlink) == 0) or (symlink[0] != "/"):
                    symlink = "/" + symlink
            else:
                symlink = "<error>"
        return symlink
