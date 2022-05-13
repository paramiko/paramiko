# Copyright (C) 2021 Lew Gordon <lew.gordon@genesys.com>
# Copyright (C) 2022 Patrick Spendrin <ps_ml@gmx.de>
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

import os.path
import time

PIPE_NAME = r"\\.\pipe\openssh-ssh-agent"


def can_talk_to_agent():
    # use os.listdir() instead of os.path.exists(), because os.path.exists()
    # uses CreateFileW() API and the pipe cannot be reopen unless the server
    # calls DisconnectNamedPipe().
    dir_, name = os.path.split(PIPE_NAME)
    name = name.lower()
    return any(name == n.lower() for n in os.listdir(dir_))


class OpenSSHAgentConnection:
    def __init__(self):
        while True:
            try:
                self._pipe = os.open(PIPE_NAME, os.O_RDWR | os.O_BINARY)
            except OSError as e:
                # retry when errno 22 which means that the server has not
                # called DisconnectNamedPipe() yet.
                if e.errno != 22:
                    raise
            else:
                break
            time.sleep(0.1)

    def send(self, data):
        return os.write(self._pipe, data)

    def recv(self, n):
        return os.read(self._pipe, n)

    def close(self):
        return os.close(self._pipe)
