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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import os.path

PIPE_NAME = r"\\.\pipe\openssh-ssh-agent"


def can_talk_to_agent():
    return os.path.exists(PIPE_NAME)


class OpenSSHAgentConnection:
    def __init__(self):
        self._pipe = open(PIPE_NAME, "rb+", buffering=0)

    def send(self, data):
        return self._pipe.write(data)

    def recv(self, n):
        return self._pipe.read(n)

    def close(self):
        return self._pipe.close()
