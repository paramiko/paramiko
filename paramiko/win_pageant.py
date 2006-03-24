# Copyright (C) 2005 John Arbash-Meinel <john@arbash-meinel.com>
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
Functions for communicating with Pageant, the basic windows ssh agent program.
"""

import os
import struct

# if you're on windows, you should have these, i guess?
try:
    import win32ui
    import win32api
    import win32con
    import mmapfile
    _has_win32all = True
except ImportError:
    _has_win32all = False


try:
    import ctypes
    _has_ctypes = True
except ImportError:
    _has_ctypes = False
else:
    class _COPYDATASTRUCT(ctypes.Structure):
        """This is a mapping to the Win32 COPYDATASTRUCT.

        typedef struct tagCOPYDATASTRUCT {
            ULONG_PTR dwData;
            DWORD cbData;
            PVOID lpData;
        } COPYDATASTRUCT, *PCOPYDATASTRUCT;
        """
        _fields_ = [ ('dwData', ctypes.c_ulong) #I think this is right
                   , ('cbData', ctypes.c_ulong)
                   , ('lpData', ctypes.c_void_p)
                   ]


_AGENT_COPYDATA_ID = 0x804e50ba
_AGENT_MAX_MSGLEN = 8192


def can_talk_to_agent():
    """
    Check to see if there is a "Pageant" agent we can talk to.

    This checks both if we have the required libraries (win32all)
    and if there is a Pageant currently running.
    """
    if not _has_win32all or not _has_ctypes:
        return False
    hwnd = win32ui.FindWindow('Pageant', 'Pageant')
    if not hwnd:
        return False
    return True


def _query_pageant(msg):
    hwnd = win32ui.FindWindow('Pageant', 'Pageant')
    if not hwnd:
        # Raise a failure to connect exception
        return None

    # I have a feeling that GetCurrentThreadId is just a
    # way to ensure that we have a unique map name
    mapname = 'PageantRequest%08x' % (win32api.GetCurrentThreadId())
    # Created a named memory map
    map = mmapfile.mmapfile('', mapname, _AGENT_MAX_MSGLEN)
    try:
        map.write(msg)

        cds = _COPYDATASTRUCT(_AGENT_COPYDATA_ID, 1 + len(mapname), ctypes.c_char_p(mapname))

        response = hwnd.SendMessage(win32con.WM_COPYDATA, None, ctypes.byref(cds))
        if response > 0:
            retlen = 4 + struct.unpack('i', map.read(4))
            return map.read(retlen)

        return None
    finally:
        # This may be done automatically.
        map.close()


class PageantConnection (object):
    """
    Mock "connection" to an agent which roughly approximates the behavior of
    a unix local-domain socket (as used by Agent).  Requests are sent to the
    pageant daemon via special Windows magick, and responses are buffered back
    for subsequent reads.
    """

    def __init__(self):
        self._response = None
    
    def send(self, data):
        self._response = _query_pageant(data)
    
    def recv(self, n):
        if self._response is None:
            return ''
        ret = self._response[:n]
        self._response = self._response[n:]
        if self._response == '':
            self._response = None
        return ret

    def close(self):
        pass
