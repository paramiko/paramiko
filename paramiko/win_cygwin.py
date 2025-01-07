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
import socket
import struct


def can_talk_to_agent():
    pipe_name = os.environ.get("SSH_AUTH_SOCK")
    dir_, name = os.path.split(pipe_name)
    name = name.lower()
    return any(name == n.lower() for n in os.listdir(dir_))

def conv_guid(s):
    parts = s.split("-")
    int_parts = [int(part, 16) for part in parts]
    return b"".join([struct.pack("<I"), part) for part in int_parts])


# https://stackoverflow.com/questions/23086038/what-mechanism-is-used-by-msys-cygwin-to-emulate-unix-domain-sockets
def read_socket_info(file_path):
    with open(file_path, "r") as f:
        data = f.read().strip()
    # cygwin implementation
    # !<socket >59108 s 282F93E1-9E2D051A-46B57EFC-64A1852F
    # msysgit implementation
    # !<socket >59108 282F93E1-9E2D051A-46B57EFC-64A1852F
    parts = data.split()
    if len(parts) == 4:
        tag, port, tag2, guid = parts
    else:
        tag, port, guid = parts
    port = int(port[1:])
    guid = guid[:-1]  # cut \x00

    guid_bytes = conv_guid(guid)
    return guid_bytes, port


class OpenCygwinSSHAgentConnection:
    def __init__(self):
        try:
            pipe_name = os.environ.get("SSH_AUTH_SOCK")
            guid, port = read_socket_info(pipe_name)

            self._conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._conn.connect(("localhost", port))

            # sends the 4 random numbers GUID to the server
            self._conn.sendall(guid)

            client_guid = self._conn.recv(16)
            if client_guid != guid:
                self._conn.close()
                return

            # sends 3 32 bit numbers: The pid, the uid and gid
            pid = os.getpid()
            uid = 0
            gid = 0
            self._conn.sendall(struct.pack("iii", pid, uid, gid))

            data = self._conn.recv(12)
            s_pid, s_uid, s_gid = struct.unpack("iii", data)

        except:
            self._conn.close()

    def send(self, data):
        return self._conn.sendall(data)

    def recv(self, n):
        return self._conn.recv(n)

    def close(self):
        self._conn.close()
