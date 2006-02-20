# Copyright (C) 2003-2006 Robey Pointer <robey@lag.net>
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
Abstraction of a one-way pipe where the read end can be used in select().
Normally this is trivial, but Windows makes it nearly impossible.
"""

import sys
import os
import socket


def make_pipe ():
    if sys.platform[:3] != 'win':
        p = PosixPipe()
    else:
        p = WindowsPipe()
    return p


class PosixPipe (object):
    def __init__ (self):
        self._rfd, self._wfd = os.pipe()
        self._set = False
        self._forever = False
    
    def close (self):
        os.close(self._rfd)
        os.close(self._wfd)
    
    def fileno (self):
        return self._rfd

    def clear (self):
        if not self._set or self._forever:
            return
        os.read(self._rfd, 1)
        self._set = False
    
    def set (self):
        if self._set:
            return
        self._set = True
        os.write(self._wfd, '*')
    
    def set_forever (self):
        self._forever = True
        self.set()


class WindowsPipe (object):
    """
    On Windows, only an OS-level "WinSock" may be used in select(), but reads
    and writes must be to the actual socket object.
    """
    def __init__ (self):
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv.bind(('127.0.0.1', 0))
        serv.listen(1)
    
        # need to save sockets in _rsock/_wsock so they don't get closed
        self._rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._rsock.connect(('127.0.0.1', serv.getsockname()[1]))
    
        self._wsock, addr = serv.accept()
        serv.close()
        self._set = False
        self._forever = False
    
    def close (self):
        self._rsock.close()
        self._wsock.close()
    
    def fileno (self):
        return self._rsock.fileno()

    def clear (self):
        if not self._set or self._forever:
            return
        self._rsock.recv(1)
        self._set = False
    
    def set (self):
        if self._set:
            return
        self._set = True
        self._wsock.send('*')

    def set_forever (self):
        self._forever = True
        self.set()
