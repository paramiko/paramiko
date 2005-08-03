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
Client-mode SFTP support.
"""

import os
from sftp import *
from sftp_attr import SFTPAttributes
from sftp_file import SFTPFile


def _to_unicode(s):
    "if a str is not ascii, decode its utf8 into unicode"
    try:
        return s.encode('ascii')
    except:
        return s.decode('utf-8')


class SFTPClient (BaseSFTP):
    """
    SFTP client object.  C{SFTPClient} is used to open an sftp session across
    an open ssh L{Transport} and do remote file operations.
    """

    def __init__(self, sock):
        """
        Create an SFTP client from an existing L{Channel}.  The channel
        should already have requested the C{"sftp"} subsystem.

        An alternate way to create an SFTP client context is by using
        L{from_transport}.

        @param sock: an open L{Channel} using the C{"sftp"} subsystem.
        @type sock: L{Channel}
        """
        BaseSFTP.__init__(self)
        self.sock = sock
        self.ultra_debug = False
        self.request_number = 1
        self._cwd = None
        if type(sock) is Channel:
            # override default logger
            transport = self.sock.get_transport()
            self.logger = util.get_logger(transport.get_log_channel() + '.' +
                                          self.sock.get_name() + '.sftp')
            self.ultra_debug = transport.get_hexdump()
        self._send_version()
    
    def __del__(self):
        self.close()

    def from_transport(selfclass, t):
        """
        Create an SFTP client channel from an open L{Transport}.

        @param t: an open L{Transport} which is already authenticated.
        @type t: L{Transport}
        @return: a new L{SFTPClient} object, referring to an sftp session
            (channel) across the transport.
        @rtype: L{SFTPClient}
        """
        chan = t.open_session()
        if chan is None:
            return None
        if not chan.invoke_subsystem('sftp'):
            raise SFTPError('Failed to invoke sftp subsystem')
        return selfclass(chan)
    from_transport = classmethod(from_transport)

    def close(self):
        """
        Close the SFTP session and its underlying channel.
        
        @since: 1.4
        """
        self.sock.close()

    def listdir(self, path='.'):
        """
        Return a list containing the names of the entries in the given C{path}.
        The list is in arbitrary order.  It does not include the special
        entries C{'.'} and C{'..'} even if they are present in the folder.
        This method is meant to mirror C{os.listdir} as closely as possible.
        For a list of full L{SFTPAttributes} objects, see L{listdir_attr}.

        @param path: path to list (defaults to C{'.'})
        @type path: str
        @return: list of filenames
        @rtype: list of str
        """
        return [f.filename for f in self.listdir_attr(path)]
        
    def listdir_attr(self, path='.'):
        """
        Return a list containing L{SFTPAttributes} objects corresponding to
        files in the given C{path}.  The list is in arbitrary order.  It does
        not include the special entries C{'.'} and C{'..'} even if they are
        present in the folder.

        @param path: path to list (defaults to C{'.'})
        @type path: str
        @return: list of attributes
        @rtype: list of L{SFTPAttributes}
        
        @since: 1.2
        """
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_OPENDIR, path)
        if t != CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_string()
        filelist = []
        while True:
            try:
                t, msg = self._request(CMD_READDIR, handle)
            except EOFError, e:
                # done with handle
                break
            if t != CMD_NAME:
                raise SFTPError('Expected name response')
            count = msg.get_int()
            for i in range(count):
                filename = _to_unicode(msg.get_string())
                longname = _to_unicode(msg.get_string())
                attr = SFTPAttributes._from_msg(msg, filename)
                if (filename != '.') and (filename != '..'):
                    filelist.append(attr)
        self._request(CMD_CLOSE, handle)
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

        The file will be buffered in standard python style by default, but
        can be altered with the C{bufsize} parameter.  C{0} turns off
        buffering, C{1} uses line buffering, and any number greater than 1
        (C{>1}) uses that specific buffer size.

        @param filename: name of the file to open.
        @type filename: string
        @param mode: mode (python-style) to open in.
        @type mode: string
        @param bufsize: desired buffering (-1 = default buffer size)
        @type bufsize: int
        @return: a file object representing the open file.
        @rtype: SFTPFile

        @raise IOError: if the file could not be opened.
        """
        filename = self._adjust_cwd(filename)
        imode = 0
        if ('r' in mode) or ('+' in mode):
            imode |= SFTP_FLAG_READ
        if ('w' in mode) or ('+' in mode):
            imode |= SFTP_FLAG_WRITE
        if ('w' in mode):
            imode |= SFTP_FLAG_CREATE | SFTP_FLAG_TRUNC
        if ('a' in mode):
            imode |= SFTP_FLAG_APPEND
        attrblock = SFTPAttributes()
        t, msg = self._request(CMD_OPEN, filename, imode, attrblock)
        if t != CMD_HANDLE:
            raise SFTPError('Expected handle')
        handle = msg.get_string()
        return SFTPFile(self, handle, mode, bufsize)

    # python has migrated toward file() instead of open().
    # and really, that's more easily identifiable.
    file = open

    def remove(self, path):
        """
        Remove the file at the given path.

        @param path: path (absolute or relative) of the file to remove.
        @type path: string

        @raise IOError: if the path refers to a folder (directory).  Use
            L{rmdir} to remove a folder.
        """
        path = self._adjust_cwd(path)
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
        oldpath = self._adjust_cwd(oldpath)
        newpath = self._adjust_cwd(newpath)
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
        path = self._adjust_cwd(path)
        attr = SFTPAttributes()
        attr.st_mode = mode
        self._request(CMD_MKDIR, path, attr)

    def rmdir(self, path):
        """
        Remove the folder named C{path}.

        @param path: name of the folder to remove.
        @type path: string
        """
        path = self._adjust_cwd(path)
        self._request(CMD_RMDIR, path)

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
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_STAT, path)
        if t != CMD_ATTRS:
            raise SFTPError('Expected attributes')
        return SFTPAttributes._from_msg(msg)

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
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_LSTAT, path)
        if t != CMD_ATTRS:
            raise SFTPError('Expected attributes')
        return SFTPAttributes._from_msg(msg)

    def symlink(self, source, dest):
        """
        Create a symbolic link (shortcut) of the C{source} path at
        C{destination}.

        @param source: path of the original file.
        @type source: string
        @param dest: path of the newly created symlink.
        @type dest: string
        """
        dest = self._adjust_cwd(dest)
        if type(source) is unicode:
            source = source.encode('utf-8')
        self._request(CMD_SYMLINK, source, dest)

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
        path = self._adjust_cwd(path)
        attr = SFTPAttributes()
        attr.st_mode = mode
        self._request(CMD_SETSTAT, path, attr)
        
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
        path = self._adjust_cwd(path)
        attr = SFTPAttributes()
        attr.st_uid, attr.st_gid = uid, gid
        self._request(CMD_SETSTAT, path, attr)

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
        path = self._adjust_cwd(path)
        if times is None:
            times = (time.time(), time.time())
        attr = SFTPAttributes()
        attr.st_atime, attr.st_mtime = times
        self._request(CMD_SETSTAT, path, attr)

    def readlink(self, path):
        """
        Return the target of a symbolic link (shortcut).  You can use
        L{symlink} to create these.  The result may be either an absolute or
        relative pathname.

        @param path: path of the symbolic link file.
        @type path: str
        @return: target path.
        @rtype: str
        """
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_READLINK, path)
        if t != CMD_NAME:
            raise SFTPError('Expected name response')
        count = msg.get_int()
        if count == 0:
            return None
        if count != 1:
            raise SFTPError('Readlink returned %d results' % count)
        return _to_unicode(msg.get_string())

    def normalize(self, path):
        """
        Return the normalized path (on the server) of a given path.  This
        can be used to quickly resolve symbolic links or determine what the
        server is considering to be the "current folder" (by passing C{'.'}
        as C{path}).

        @param path: path to be normalized.
        @type path: str
        @return: normalized form of the given path.
        @rtype: str
        
        @raise IOError: if the path can't be resolved on the server
        """
        path = self._adjust_cwd(path)
        t, msg = self._request(CMD_REALPATH, path)
        if t != CMD_NAME:
            raise SFTPError('Expected name response')
        count = msg.get_int()
        if count != 1:
            raise SFTPError('Realpath returned %d results' % count)
        return _to_unicode(msg.get_string())
    
    def chdir(self, path):
        """
        Change the "current directory" of this SFTP session.  Since SFTP
        doesn't really have the concept of a current working directory, this
        is emulated by paramiko.  Once you use this method to set a working
        directory, all operations on this SFTPClient object will be relative
        to that path.
        
        @param path: new current working directory
        @type path: str
        
        @raise IOError: if the requested path doesn't exist on the server
        
        @since: 1.4
        """
        self._cwd = self.normalize(path)
    
    def getcwd(self):
        """
        Return the "current working directory" for this SFTP session, as
        emulated by paramiko.  If no directory has been set with L{chdir},
        this method will return C{None}.
        
        @return: the current working directory on the server, or C{None}
        @rtype: str
        
        @since: 1.4
        """
        return self._cwd
    
    def put(self, localpath, remotepath):
        """
        Copy a local file (C{localpath}) to the SFTP server as C{remotepath}.
        Any exception raised by operations will be passed through.  This
        method is primarily provided as a convenience.
        
        @param localpath: the local file to copy
        @type localpath: str
        @param remotepath: the destination path on the SFTP server
        @type remotepath: str
        
        @since: 1.4
        """
        fl = file(localpath, 'rb')
        fr = self.file(remotepath, 'wb')
        size = 0
        while True:
            data = fl.read(32768)
            if len(data) == 0:
                break
            fr.write(data)
            size += len(data)
        fl.close()
        fr.close()
        s = self.stat(remotepath)
        if s.st_size != size:
            raise IOError('size mismatch in put!  %d != %d' % (s.st_size, size))
    
    def get(self, remotepath, localpath):
        """
        Copy a remote file (C{remotepath}) from the SFTP server to the local
        host as C{localpath}.  Any exception raised by operations will be
        passed through.  This method is primarily provided as a convenience.
        
        @param remotepath: the remote file to copy
        @type remotepath: str
        @param localpath: the destination path on the local host
        @type localpath: str
        
        @since: 1.4
        """
        fr = self.file(remotepath, 'rb')
        fl = file(localpath, 'wb')
        size = 0
        while True:
            data = fr.read(32768)
            if len(data) == 0:
                break
            fl.write(data)
            size += len(data)
        fl.close()
        fr.close()
        s = os.stat(localpath)
        if s.st_size != size:
            raise IOError('size mismatch in get!  %d != %d' % (s.st_size, size))


    ###  internals...


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
                item._pack(msg)
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
        if code == SFTP_OK:
            return
        elif code == SFTP_EOF:
            raise EOFError(text)
        else:
            raise IOError(text)
    
    def _adjust_cwd(self, path):
        """
        Return an adjusted path if we're emulating a "current working
        directory" for the server.
        """
        if type(path) is unicode:
            path = path.encode('utf-8')
        if self._cwd is None:
            return path
        if (len(path) > 0) and (path[0] == '/'):
            # absolute path
            return path
        return self._cwd + '/' + path


class SFTP (SFTPClient):
    "an alias for L{SFTPClient} for backwards compatability"
    pass
