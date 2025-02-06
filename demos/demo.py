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
Demonstrates how to open a shell at an SSH server, including how to support
SSH agents and different types of keys.
"""

from binascii import hexlify
import getpass
import os
import socket
import sys
import traceback

import paramiko

try:
    import interactive
except ImportError:
    from . import interactive


def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """

    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return

    for key in agent_keys:
        print("Trying ssh-agent key %s" % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            print("... success!")
            return
        except paramiko.SSHException:
            print("... nope.")


def manual_auth(username, hostname):
    default_auth = "p"
    auth = input(
        "Auth by (p)assword, (r)sa key, (d)ss key, or (e)25519 key? [%s] "
        % default_auth
    )
    if len(auth) == 0:
        auth = default_auth

    if auth == "r":
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_rsa")
        path = input("RSA key [%s]: " % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.RSAKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass("RSA key password: ")
            key = paramiko.RSAKey.from_private_key_file(path, password)
        t.auth_publickey(username, key)
    elif auth == "d":
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_dsa")
        path = input("DSS key [%s]: " % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.DSSKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass("DSS key password: ")
            key = paramiko.DSSKey.from_private_key_file(path, password)
        t.auth_publickey(username, key)
    elif auth == "e":
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_ed25519")
        path = input("ed25519 key [%s]: " % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.Ed25519Key.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass("ed25519 key password: ")
            key = paramiko.Ed25519Key.from_private_key_file(path, password)
        t.auth_publickey(username, key)
    else:
        pw = getpass.getpass("Password for %s@%s: " % (username, hostname))
        t.auth_password(username, pw)


# setup logging
paramiko.util.log_to_file("demo.log")

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
port = 22
if hostname.find(":") >= 0:
    hostname, portstr = hostname.split(":")
    port = int(portstr)

# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))
except Exception as e:
    print("*** Connect failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    t = paramiko.Transport(sock)
    try:
        t.start_client()
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

    try:
        keys = paramiko.util.load_host_keys(
            os.path.expanduser("~/.ssh/known_hosts")
        )
    except IOError:
        try:
            keys = paramiko.util.load_host_keys(
                os.path.expanduser("~/ssh/known_hosts")
            )
        except IOError:
            print("*** Unable to open host keys file")
            keys = {}

    # check server's host key -- this is important.
    key = t.get_remote_server_key()
    if hostname not in keys:
        print("*** WARNING: Unknown host key!")
    elif key.get_name() not in keys[hostname]:
        print("*** WARNING: Unknown host key!")
    elif keys[hostname][key.get_name()] != key:
        print("*** WARNING: Host key has changed!!!")
        sys.exit(1)
    else:
        print("*** Host key OK.")

    # get username
    if username == "":
        default_username = getpass.getuser()
        username = input("Username [%s]: " % default_username)
        if len(username) == 0:
            username = default_username

    agent_auth(t, username)
    if not t.is_authenticated():
        manual_auth(username, hostname)
    if not t.is_authenticated():
        print("*** Authentication failed. :(")
        t.close()
        sys.exit(1)

    chan = t.open_session()
    chan.get_pty()
    chan.invoke_shell()
    print("*** Here we go!\n")
    interactive.interactive_shell(chan)
    chan.close()
    t.close()

except Exception as e:
    print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
