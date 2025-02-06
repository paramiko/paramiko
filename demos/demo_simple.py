#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
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

"""
Demonstrates how to open a shell at an SSH server, using basic password
authentication or GSSAPI.
"""

import getpass
import sys
import traceback

import paramiko

try:
    import interactive
except ImportError:
    from . import interactive


# setup logging
paramiko.util.log_to_file("demo_simple.log")
# Paramiko client configuration
UseGSSAPI = (
    paramiko.GSS_AUTH_AVAILABLE
)  # enable "gssapi-with-mic" authentication, if supported by your python installation
DoGSSAPIKeyExchange = (
    paramiko.GSS_AUTH_AVAILABLE
)  # enable "gssapi-kex" key exchange, if supported by your python installation
port = 22

# get hostname
username = ""
if len(sys.argv) > 1:
    hostname = sys.argv[1]
    if hostname.find("@") >= 0:
        username, hostname = hostname.split("@")
else:
    hostname = input("Hostname: ")
if len(hostname) == 0:
    print("*** Hostname required.")
    sys.exit(1)

if hostname.find(":") >= 0:
    hostname, portstr = hostname.split(":")
    port = int(portstr)


# get username
if username == "":
    default_username = getpass.getuser()
    username = input("Username [%s]: " % default_username)
    if len(username) == 0:
        username = default_username
if not UseGSSAPI and not DoGSSAPIKeyExchange:
    password = getpass.getpass("Password for %s@%s: " % (username, hostname))


# now, connect and use paramiko Client to negotiate SSH2 across the connection
try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    print("*** Connecting...")
    if not UseGSSAPI and not DoGSSAPIKeyExchange:
        client.connect(hostname, port, username, password)
    else:
        try:
            client.connect(
                hostname,
                port,
                username,
                gss_auth=UseGSSAPI,
                gss_kex=DoGSSAPIKeyExchange,
            )
        except Exception:
            traceback.print_exc()
            password = getpass.getpass(
                "Password for %s@%s: " % (username, hostname)
            )
            client.connect(hostname, port, username, password)

    chan = client.invoke_shell()
    print(repr(client.get_transport()))
    print("*** Here we go!\n")
    interactive.interactive_shell(chan)
    chan.close()
    client.close()

except Exception as e:
    print("*** Caught exception: %s: %s" % (e.__class__, e))
    traceback.print_exc()
    try:
        client.close()
    except:
        pass
    sys.exit(1)
