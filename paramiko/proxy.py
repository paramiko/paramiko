# Copyright (C) 2012  Yipit, Inc <coders@yipit.com>
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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import os
import shlex
import signal
from select import select
import socket
import time

# Try-and-ignore import so platforms w/o subprocess (eg Google App Engine) can
# still import paramiko.
subprocess, subprocess_import_error = None, None
try:
    import subprocess
except ImportError as e:
    subprocess_import_error = e

from paramiko.ssh_exception import ProxyCommandFailure
from paramiko.util import ClosingContextManager


class ProxyCommand(ClosingContextManager):
    """
    Wraps a subprocess running ProxyCommand-driven programs.

    This class implements a the socket-like interface needed by the
    `.Transport` and `.Packetizer` classes. Using this class instead of a
    regular socket makes it possible to talk with a Popen'd command that will
    proxy traffic between the client and a server hosted in another machine.

    Instances of this class may be used as context managers.
    """

    def __init__(self, command_line):
        """
        Create a new CommandProxy instance. The instance created by this
        class can be passed as an argument to the `.Transport` class.

        :param str command_line:
            the command that should be executed and used as the proxy.
        """
        if subprocess is None:
            raise subprocess_import_error
        self.cmd = shlex.split(command_line)
        self.process = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.timeout = None

    def send(self, content):
        """
        Write the content received from the SSH client to the standard
        input of the forked command.

        :param str content: string to be sent to the forked command
        """
        try:
            self.process.stdin.write(content)
        except IOError as e:
            # There was a problem with the child process. It probably
            # died and we can't proceed. The best option here is to
            # raise an exception informing the user that the informed
            # ProxyCommand is not working.
            raise ProxyCommandFailure(" ".join(self.cmd), e.strerror)
        return len(content)

    def recv(self, size):
        """
        Read from the standard output of the forked program.

        :param int size: how many chars should be read

        :return: the string of bytes read, which may be shorter than requested
        """
        try:
            buffer = b""
            start = time.monotonic()
            while len(buffer) < size:
                select_timeout = None
                if self.timeout is not None:
                    elapsed = time.monotonic() - start
                    if elapsed >= self.timeout:
                        raise socket.timeout()
                    select_timeout = self.timeout - elapsed

                r, w, x = select([self.process.stdout], [], [], select_timeout)
                if r and r[0] == self.process.stdout:
                    buffer += os.read(
                        self.process.stdout.fileno(), size - len(buffer)
                    )
            return buffer
        except socket.timeout:
            if buffer:
                # Don't raise socket.timeout, return partial result instead
                return buffer
            raise  # socket.timeout is a subclass of IOError
        except IOError as e:
            raise ProxyCommandFailure(" ".join(self.cmd), e.strerror)

    def close(self):
        os.kill(self.process.pid, signal.SIGTERM)

    @property
    def closed(self):
        return self.process.returncode is not None

    @property
    def _closed(self):
        # Concession to Python 3 socket-like API
        return self.closed

    def settimeout(self, timeout):
        self.timeout = timeout
