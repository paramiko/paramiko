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

import base64

import paramiko


_pubkey_types = {"ssh-rsa": paramiko.RSAKey, "ssh-dss": paramiko.DSSKey}


def _load_pubkey_from_file(keyfile):
    line = keyfile.readline()

    # skip over comments or blank lines
    while line[0] == "#" or line[0] == "\n":
        line = keyfile.readline()

    # don"t load what looks like a private key
    if line.startswith("-----BEGIN"):
        return None

    # fields[0] = key type
    # fields[1] = base64-encoded key blob
    fields = line.strip().split(" ", 1)
    if len(fields) != 2:
        return None

    pkclass = _pubkey_types[fields[0]]
    pubkey = pkclass(data=base64.decodestring(fields[1]))

    return pubkey


def load_pubkey_from_file(keyfile):
    try:
        if type(keyfile) is str:
            with open(keyfile, "r") as f:
                pubkey = _load_pubkey_from_file(f)
        else:
            pubkey = _load_pubkey_from_file(keyfile)
    except:
        raise paramiko.SSHException("error loading public key from file")

    return pubkey
