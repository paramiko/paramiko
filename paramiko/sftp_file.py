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

"""
L{SFTPFile}
"""

from common import *
from sftp import *
from file import BufferedFile
from sftp_attr import SFTPAttributes


class SFTPFile (BufferedFile):
    """
    Proxy object for a file on the remote server, in client mode SFTP.
    """

    # Some sftp servers will choke if you send read/write requests larger than
    # this size.
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)

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
        self.sftp.sock.settimeout(timeout)

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a float) associated with the socket
        or ssh L{Channel} used for this file.

        @see: L{Channel.gettimeout}
        @rtype: float
        """
        return self.sftp.sock.gettimeout()

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode on the underiying socket or ssh
        L{Channel}.

        @see: L{Channel.setblocking}
        @param blocking: 0 to set non-blocking mode; non-0 to set blocking
        mode.
        @type blocking: int
        """
        self.sftp.sock.setblocking(blocking)

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


    ###  internals...


    def _get_size(self):
        try:
            return self.stat().st_size
        except:
            return 0
