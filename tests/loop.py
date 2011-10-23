# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
...
"""

import threading, socket


class LoopSocket (object):
    """
    A LoopSocket looks like a normal socket, but all data written to it is
    delivered on the read-end of another LoopSocket, and vice versa.  It's
    like a software "socketpair".
    """
    
    def __init__(self):
        self.__in_buffer = ''
        self.__lock = threading.Lock()
        self.__cv = threading.Condition(self.__lock)
        self.__timeout = None
        self.__mate = None

    def close(self):
        self.__unlink()
        try:
            self.__lock.acquire()
            self.__in_buffer = ''
        finally:
            self.__lock.release()

    def send(self, data):
        if self.__mate is None:
            # EOF
            raise EOFError()
        self.__mate.__feed(data)
        return len(data)

    def recv(self, n):
        self.__lock.acquire()
        try:
            if self.__mate is None:
                # EOF
                return ''
            if len(self.__in_buffer) == 0:
                self.__cv.wait(self.__timeout)
            if len(self.__in_buffer) == 0:
                raise socket.timeout
            if n < self.__in_buffer:
                out = self.__in_buffer[:n]
                self.__in_buffer = self.__in_buffer[n:]
            else:
                out = self.__in_buffer
                self.__in_buffer = ''
            return out
        finally:
            self.__lock.release()

    def settimeout(self, n):
        self.__timeout = n

    def link(self, other):
        self.__mate = other
        self.__mate.__mate = self

    def __feed(self, data):
        self.__lock.acquire()
        try:
            self.__in_buffer += data
            self.__cv.notifyAll()
        finally:
            self.__lock.release()
            
    def __unlink(self):
        m = None
        self.__lock.acquire()
        try:
            if self.__mate is not None:
                m = self.__mate
                self.__mate = None
        finally:
            self.__lock.release()
        if m is not None:
            m.__unlink()


