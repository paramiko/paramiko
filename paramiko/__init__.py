#!/usr/bin/python

# Copyright (C) 2003-2004 Robey Pointer <robey@lag.net>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Foobar; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
I{Paramiko} (a combination of the esperanto words for "paranoid" and "friend")
is a module for python 2.3 or greater that implements the SSH2 protocol for
secure (encrypted and authenticated) connections to remote machines.  Unlike
SSL (aka TLS), the SSH2 protocol does not require heirarchical certificates
signed by a powerful central authority.  You may know SSH2 as the protocol that
replaced C{telnet} and C{rsh} for secure access to remote shells, but the
protocol also includes the ability to open arbitrary channels to remote
services across an encrypted tunnel.  (This is how C{sftp} works, for example.)

To use this package, pass a socket (or socket-like object) to a L{Transport},
and use L{start_server <paramiko.transport.BaseTransport.start_server>} or
L{start_client <paramiko.transport.BaseTransport.start_client>} to negoatite
with the remote host as either a server or client.  As a client, you are
responsible for authenticating using a password or private key, and checking
the server's host key.  I{(Key signature and verification is done by paramiko,
but you will need to provide private keys and check that the content of a
public key matches what you expected to see.)}  As a server, you are
responsible for deciding which users, passwords, and keys to allow, and what
kind of channels to allow.

Once you have finished, either side may request flow-controlled L{Channel}s to
the other side, which are python objects that act like sockets, but send and
receive data over the encrypted session.

Paramiko is written entirely in python (no C or platform-dependent code) and is
released under the GNU Lesser General Public License (LGPL).

Website: U{http://www.lag.net/~robey/paramiko/}

@version: 0.9 (gyarados)
@author: Robey Pointer
@contact: robey@lag.net
@license: GNU Lesser General Public License (LGPL)
"""

import sys

if sys.version_info < (2, 2):
    raise RuntimeError('You need python 2.2 for this module.')


__author__ = "Robey Pointer <robey@lag.net>"
__date__ = "31 May 2004"
__version__ = "0.9-gyarados"
__license__ = "GNU Lesser General Public License (LGPL)"


import transport, auth_transport, channel, rsakey, dsskey, message, ssh_exception, sftp

Transport = auth_transport.Transport
Channel = channel.Channel
RSAKey = rsakey.RSAKey
DSSKey = dsskey.DSSKey
SSHException = ssh_exception.SSHException
Message = message.Message
PasswordRequiredException = ssh_exception.PasswordRequiredException
SFTP = sftp.SFTP


__all__ = [ 'Transport',
            'Channel',
            'RSAKey',
            'DSSKey',
            'Message',
            'SSHException',
            'PasswordRequiredException',
            'SFTP',
            'transport',
            'auth_transport',
            'channel',
            'rsakey',
            'dsskey',
            'pkey',
            'message',
            'ssh_exception',
            'sftp',
            'util' ]
