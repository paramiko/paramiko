# Copyright (C) 2012  Yipit, Inc <coders@yipit.com>
#
# This file is part of ssh.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
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
# 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA.

import os
from shlex import split as shlsplit
from subprocess import Popen, PIPE

from ssh.ssh_exception import BadProxyCommand


class ProxyCommand(object):
    """
    A proxy based on the program informed in the ProxyCommand config.

    This class implements a the interface needed by both L{Transport}
    and L{Packetizer} classes. Using this class instead of a regular
    socket makes it possible to talk with a popened command that will
    proxy all the conversation between the client and a server hosted in
    another machine.
    """

    def __init__(self, command_line):
        """
        Create a new CommandProxy instance. The instance created by this
        class should be passed as argument to the L{Transport} class.

        @param command_line: the command that should be executed and
         used as the proxy.
        @type command_line: str
        """
        self.cmd = shlsplit(command_line)
        self.process = Popen(self.cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def send(self, content):
        """
        Write the content received from the SSH client to the standard
        input of the forked command.

        @param content: string to be sent to the forked command
        @type content: str
        """
        try:
            self.process.stdin.write(content)
        except IOError, exc:
            # There was a problem with the child process. It probably
            # died and we can't proceed. The best option here is to
            # raise an exception informing the user that the informed
            # ProxyCommand is not working.
            raise BadProxyCommand(' '.join(self.cmd), exc.strerror)
        return len(content)

    def recv(self, size):
        """
        Read from the standard output of the forked program

        @param size: how many chars should be read
        @type size: int

        @return: the length of the readed content
        @rtype: int
        """
        try:
            return os.read(self.process.stdout.fileno(), size)
        except IOError, exc:
            raise BadProxyCommand(' '.join(self.cmd), exc.strerror)

    def close(self):
        self.process.terminate()

    def settimeout(self, timeout):
        pass
