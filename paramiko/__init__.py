# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
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
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
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

Website: U{http://www.lag.net/paramiko/}

@version: 1.3.1 (nidoran)
@author: Robey Pointer
@contact: robey@lag.net
@license: GNU Lesser General Public License (LGPL)
"""

import sys

if sys.version_info < (2, 2):
    raise RuntimeError('You need python 2.2 for this module.')


__author__ = "Robey Pointer <robey@lag.net>"
__date__ = "28 Jun 2005"
__version__ = "1.3.1 (nidoran)"
__license__ = "GNU Lesser General Public License (LGPL)"


import transport, auth_transport, channel, rsakey, dsskey, message
import ssh_exception, file, packet, agent, server, util
import sftp_client, sftp_attr, sftp_handle, sftp_server, sftp_si

randpool = transport.randpool
Transport = auth_transport.Transport
Channel = channel.Channel
RSAKey = rsakey.RSAKey
DSSKey = dsskey.DSSKey
SSHException = ssh_exception.SSHException
Message = message.Message
PasswordRequiredException = ssh_exception.PasswordRequiredException
BadAuthenticationType = ssh_exception.BadAuthenticationType
SFTP = sftp_client.SFTP
SFTPClient = sftp_client.SFTPClient
SFTPServer = sftp_server.SFTPServer
from sftp import SFTPError
SFTPAttributes = sftp_attr.SFTPAttributes
SFTPHandle = sftp_handle.SFTPHandle
SFTPServerInterface = sftp_si.SFTPServerInterface
ServerInterface = server.ServerInterface
SubsystemHandler = server.SubsystemHandler
SecurityOptions = transport.SecurityOptions
BufferedFile = file.BufferedFile
Packetizer = packet.Packetizer
Agent = agent.Agent

from common import AUTH_SUCCESSFUL, AUTH_PARTIALLY_SUCCESSFUL, AUTH_FAILED, \
     OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,  OPEN_FAILED_CONNECT_FAILED, \
     OPEN_FAILED_UNKNOWN_CHANNEL_TYPE, OPEN_FAILED_RESOURCE_SHORTAGE

from sftp import SFTP_OK, SFTP_EOF, SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED, SFTP_FAILURE, \
     SFTP_BAD_MESSAGE, SFTP_NO_CONNECTION, SFTP_CONNECTION_LOST, SFTP_OP_UNSUPPORTED

__all__ = [ 'Transport',
            'SecurityOptions',
            'SubsystemHandler',
            'Channel',
            'RSAKey',
            'DSSKey',
            'Agent',
            'Message',
            'SSHException',
            'PasswordRequiredException',
            'BadAuthenticationType',
            'SFTP',
            'SFTPHandle',
            'SFTPClient',
            'SFTPServer',
            'SFTPError',
            'SFTPAttributes',
            'SFTPServerInterface'
            'ServerInterface',
            'BufferedFile',
            'transport',
            'auth_transport',
            'channel',
            'rsakey',
            'dsskey',
            'pkey',
            'message',
            'ssh_exception',
            'sftp',
            'sftp_client',
            'sftp_server',
            'sftp_attr',
            'sftp_file',
            'sftp_si',
            'sftp_handle',
            'server',
            'file',
            'util' ]
