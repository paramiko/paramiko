# Copyright (C) 2021 Lew Gordon <lew.gordon@genesys.com>
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
import struct

import pywintypes
import win32pipe, win32file

PIPE_NAME = r'\\.\pipe\openssh-ssh-agent'

def can_talk_to_agent():
    try:
        return win32file.FindFilesW(PIPE_NAME)[0][0] == 128
    except pywintypes.error as e:
        if e.winerror == 18: # ERROR_NO_MORE_FILES https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
            return False
        raise e

class NamedPipeConnection:
    def __init__(self):
        self._response = None
        self._handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        win32pipe.WaitNamedPipe(PIPE_NAME, 20_000)
        win32pipe.SetNamedPipeHandleState(self._handle, win32pipe.PIPE_READMODE_BYTE, None, None)
    
    def send(self, data):
        win32file.WriteFile(self._handle, data)
        # https://tools.ietf.org/html/draft-miller-ssh-agent-04#section-3
        message_len = win32file.ReadFile(self._handle, 4)[1]
        buf_size = struct.unpack('>I', message_len)[0]
        ret = win32file.ReadFile(self._handle, buf_size)
        self._response = message_len + ret[1]

    def recv(self, n):
        if not self._response:
            return ''
        
        ret = self._response[:n]
        self._response = self._response[n:]
        if not self._response:
            self._response = None
        return ret

    def close(self):
        win32file.CloseHandle(self._handle)
