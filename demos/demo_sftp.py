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

# based on code provided by raymond mosteller (thanks!)

import base64
import getpass
import os
import socket
import sys
import traceback

import paramiko
from paramiko.py3compat import input


# setup logging
paramiko.util.log_to_file("demo_sftp.log")

# Paramiko client configuration
UseGSSAPI = True  # enable GSS-API / SSPI authentication
DoGSSAPIKeyExchange = True
Port = 22

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
    Port = int(portstr)


# get username
if username == "":
    default_username = getpass.getuser()
    username = input("Username [%s]: " % default_username)
    if len(username) == 0:
        username = default_username
if not UseGSSAPI:
    password = getpass.getpass("Password for %s@%s: " % (username, hostname))
else:
    password = None


# get host key, if we know one
hostkeytype = None
hostkey = None
try:
    host_keys = paramiko.util.load_host_keys(
        os.path.expanduser("~/.ssh/known_hosts")
    )
except IOError:
    try:
        # try ~/ssh/ too, because windows can't have a folder named ~/.ssh/
        host_keys = paramiko.util.load_host_keys(
            os.path.expanduser("~/ssh/known_hosts")
        )
    except IOError:
        print("*** Unable to open host keys file")
        host_keys = {}

if hostname in host_keys:
    hostkeytype = host_keys[hostname].keys()[0]
    hostkey = host_keys[hostname][hostkeytype]
    print("Using host key of type %s" % hostkeytype)


# now, connect and use paramiko Transport to negotiate SSH2 across the connection
try:
    t = paramiko.Transport((hostname, Port))
    t.connect(
        hostkey,
        username,
        password,
        gss_host=socket.getfqdn(hostname),
        gss_auth=UseGSSAPI,
        gss_kex=DoGSSAPIKeyExchange,
    )
    sftp = paramiko.SFTPClient.from_transport(t)

    # dirlist on remote host
    dirlist = sftp.listdir(".")
    print("Dirlist: %s" % dirlist)

    # copy this demo onto the server
    try:
        sftp.mkdir("demo_sftp_folder")
    except IOError:
        print("(assuming demo_sftp_folder/ already exists)")
    with sftp.open("demo_sftp_folder/README", "w") as f:
        f.write("This was created by demo_sftp.py.\n")
    with open("demo_sftp.py", "r") as f:
        data = f.read()
    sftp.open("demo_sftp_folder/demo_sftp.py", "w").write(data)
    print("created demo_sftp_folder/ on the server")

    # copy the README back here
    with sftp.open("demo_sftp_folder/README", "r") as f:
        data = f.read()
    with open("README_demo_sftp", "w") as f:
        f.write(data)
    print("copied README back here")

    # BETTER: use the get() and put() methods
    sftp.put("demo_sftp.py", "demo_sftp_folder/demo_sftp.py")
    sftp.get("demo_sftp_folder/README", "README_demo_sftp")

    t.close()

except Exception as e:
    print("*** Caught exception: %s: %s" % (e.__class__, e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
