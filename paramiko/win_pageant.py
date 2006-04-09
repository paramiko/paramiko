# Copyright (C) 2005 John Arbash-Meinel <john@arbash-meinel.com>
# Modified up by: Todd Whiteman <ToddW@ActiveState.com>
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
import tempfile
import mmap
import array

# if you're on windows, you should have these, i guess?
try:
    import win32ui
    _has_win32all = True
except ImportError:
    _has_win32all = False


_AGENT_COPYDATA_ID = 0x804e50ba
_AGENT_MAX_MSGLEN = 8192
# Note: The WM_COPYDATA value is pulled from win32con, as a workaround
# so we do not have to import this huge library just for this one variable.
win32con_WM_COPYDATA = 74


def _get_pageant_window_object():
    try:
        hwnd = win32ui.FindWindow('Pageant', 'Pageant')
        return hwnd
    except win32ui.error:
        return None


def can_talk_to_agent():
    """
    Check to see if there is a "Pageant" agent we can talk to.

    This checks both if we have the required libraries (win32all)
    and if there is a Pageant currently running.
    """
    if not _has_win32all or not _get_pageant_window_object():
        return False
    return True


def _query_pageant(msg):
    hwnd = _get_pageant_window_object()
    if not hwnd:
        # Raise a failure to connect exception, pageant isn't running anymore!
        return None

    # Write our pageant request string into the file (pageant will read this to determine what to do)
    filename = tempfile.mktemp('.pag')
    map_filename = os.path.basename(filename)

    f = open(filename, 'w+b')
    f.write(msg )
    # Ensure the rest of the file is empty, otherwise pageant will read this
    f.write('\0' * (_AGENT_MAX_MSGLEN - len(msg)))
    # Create the shared file map that pageant will use to read from
    pymap = mmap.mmap(f.fileno(), _AGENT_MAX_MSGLEN, tagname=map_filename, access=mmap.ACCESS_WRITE)
    try:
        # Create an array buffer containing the mapped filename
        char_buffer = array.array("c", map_filename + '\0')
        char_buffer_address, char_buffer_size = char_buffer.buffer_info()
        # Create a string to use for the SendMessage function call
        cds = struct.pack("LLP", _AGENT_COPYDATA_ID, char_buffer_size, char_buffer_address)

        response = hwnd.SendMessage(win32con_WM_COPYDATA, cds)
        if response > 0:
            datalen = pymap.read(4)
            retlen = struct.unpack('>I', datalen)[0]
            return datalen + pymap.read(retlen)
        return None
    finally:
        pymap.close()
        f.close()
        # Remove the file, it was temporary only
        os.unlink(filename)


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
