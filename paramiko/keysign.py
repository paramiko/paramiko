# Copyright (C) 2014  Nicholas Mills <nlmills@g.clemson.edu>
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
import subprocess

import paramiko


class Keysign(object):
    def __init__(self, keysign_path=""):
        candidate_paths = [
            keysign_path,
            "/usr/libexec/ssh-keysign",
            "/usr/lib64/ssh/ssh-keysign",
            "/usr/libexec/openssh/ssh-keysign",
        ]

        match = None
        for path in candidate_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                match = path
                break

        if match is None:
            ae = "no ssh-keysign program found"
            raise paramiko.AuthenticationException(ae)
        self._keysign_path = match

    def sign(self, sock, blob):
        version = chr(2)

        # Construct the request
        request = paramiko.Message()
        request.add_byte(version)
        request.add_int(sock.fileno())
        request.add_string(blob)
        reqm = paramiko.Message()
        reqm.add_string(str(request))

        # Sign the request and test completion
        ksproc = subprocess.Popen(
            [self._keysign_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (so, se) = ksproc.communicate(str(reqm))
        if 0 != ksproc.returncode:
            ae = self._keysign_path + " terminated with an error: " + se
            raise paramiko.AuthenticationException(ae)

        # Send the response
        respm = paramiko.Message(so)
        response = paramiko.Message(respm.get_string())
        respver = response.get_byte()
        if version != respver:
            ae = "incompatible versions " + version + " != " + respver
            raise paramiko.AuthenticationException(ae)
        else:
            signature = response.get_string()
        return signature
