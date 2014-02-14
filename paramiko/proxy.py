# Copyright (C) 2012  Yipit, Inc <coders@yipit.com>
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
L{ProxyCommand}.
"""

from datetime import datetime
import os
from shlex import split as shlsplit
import signal
from subprocess import Popen, PIPE
from select import select
import socket

from paramiko.ssh_exception import ProxyCommandFailure


class ProxyCommand(object):
    """
    Wraps a subprocess running ProxyCommand-driven programs.

    This class implements a the socket-like interface needed by the
    L{Transport} and L{Packetizer} classes. Using this class instead of a
    regular socket makes it possible to talk with a Popen'd command that will
    proxy traffic between the client and a server hosted in another machine.
    """
    def __init__(self, command_line):
        """
        Create a new CommandProxy instance. The instance created by this
        class can be passed as an argument to the L{Transport} class.

        @param command_line: the command that should be executed and
            used as the proxy.
        @type command_line: str
        """
        self.cmd = shlsplit(command_line)
        self.process = Popen(self.cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self.timeout = None
        self.buffer = []

    def send(self, content):
        """
        Write the content received from the SSH client to the standard
        input of the forked command.

        @param content: string to be sent to the forked command
        @type content: str
        """
        try:
            self.process.stdin.write(content)
        except IOError, e:
            # There was a problem with the child process. It probably
            # died and we can't proceed. The best option here is to
            # raise an exception informing the user that the informed
            # ProxyCommand is not working.
            raise ProxyCommandFailure(' '.join(self.cmd), e.strerror)
        return len(content)

    def recv(self, size):
        """
        Read from the standard output of the forked program.

        @param size: how many chars should be read
        @type size: int

        @return: the length of the read content
        @rtype: int
        """
        try:
            start = datetime.now()
            while len(self.buffer) < size:
                if self.timeout is not None:
                    elapsed = (datetime.now() - start).microseconds
                    timeout = self.timeout * 1000 * 1000 # to microseconds
                    if elapsed >= timeout:
                        raise socket.timeout()
                r, w, x = select([self.process.stdout], [], [], 0.0)
                if r and r[0] == self.process.stdout:
                    b = os.read(self.process.stdout.fileno(), 1)
                    # Store in class-level buffer for persistence across
                    # timeouts; this makes us act more like a real socket
                    # (where timeouts don't actually drop data.)
                    self.buffer.append(b)
            result = ''.join(self.buffer)
            self.buffer = []
            return result
        except socket.timeout:
            raise # socket.timeout is a subclass of IOError
        except IOError, e:
            raise ProxyCommandFailure(' '.join(self.cmd), e.strerror)

    def close(self):
        os.kill(self.process.pid, signal.SIGTERM)

    def settimeout(self, timeout):
        self.timeout = timeout
