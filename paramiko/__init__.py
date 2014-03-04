# Copyright (C) 2003-2011  Robey Pointer <robeypointer@gmail.com>
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

import sys

if sys.version_info < (2, 5):
    raise RuntimeError('You need Python 2.5+ for this module.')


__author__ = "Jeff Forcier <jeff@bitprophet.org>"
__version__ = "1.11.4"
__version_info__ = tuple([ int(d) for d in __version__.split(".") ])
__license__ = "GNU Lesser General Public License (LGPL)"


from transport import SecurityOptions, Transport
from client import SSHClient, MissingHostKeyPolicy, AutoAddPolicy, RejectPolicy, WarningPolicy
from auth_handler import AuthHandler
from channel import Channel, ChannelFile
from ssh_exception import SSHException, PasswordRequiredException, \
    BadAuthenticationType, ChannelException, BadHostKeyException, \
    AuthenticationException, ProxyCommandFailure
from server import ServerInterface, SubsystemHandler, InteractiveQuery
from rsakey import RSAKey
from dsskey import DSSKey
from sftp import SFTPError, BaseSFTP
from sftp_client import SFTP, SFTPClient
from sftp_server import SFTPServer
from sftp_attr import SFTPAttributes
from sftp_handle import SFTPHandle
from sftp_si import SFTPServerInterface
from sftp_file import SFTPFile
from message import Message
from packet import Packetizer
from file import BufferedFile
from agent import Agent, AgentKey
from pkey import PKey
from hostkeys import HostKeys
from config import SSHConfig
from proxy import ProxyCommand

from common import AUTH_SUCCESSFUL, AUTH_PARTIALLY_SUCCESSFUL, AUTH_FAILED, \
     OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,  OPEN_FAILED_CONNECT_FAILED, \
     OPEN_FAILED_UNKNOWN_CHANNEL_TYPE, OPEN_FAILED_RESOURCE_SHORTAGE

from sftp import SFTP_OK, SFTP_EOF, SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED, SFTP_FAILURE, \
     SFTP_BAD_MESSAGE, SFTP_NO_CONNECTION, SFTP_CONNECTION_LOST, SFTP_OP_UNSUPPORTED

from common import io_sleep

__all__ = [ 'Transport',
            'SSHClient',
            'MissingHostKeyPolicy',
            'AutoAddPolicy',
            'RejectPolicy',
            'WarningPolicy',
            'SecurityOptions',
            'SubsystemHandler',
            'Channel',
            'PKey',
            'RSAKey',
            'DSSKey',
            'Message',
            'SSHException',
            'AuthenticationException',
            'PasswordRequiredException',
            'BadAuthenticationType',
            'ChannelException',
            'BadHostKeyException',
            'ProxyCommand',
            'ProxyCommandFailure',
            'SFTP',
            'SFTPFile',
            'SFTPHandle',
            'SFTPClient',
            'SFTPServer',
            'SFTPError',
            'SFTPAttributes',
            'SFTPServerInterface',
            'ServerInterface',
            'BufferedFile',
            'Agent',
            'AgentKey',
            'HostKeys',
            'SSHConfig',
            'util',
            'io_sleep' ]
