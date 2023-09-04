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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

# flake8: noqa
import sys
from paramiko._version import __version__, __version_info__
from paramiko.transport import (
    SecurityOptions,
    Transport,
    ServiceRequestingTransport,
)
from paramiko.client import (
    SSHClient,
    MissingHostKeyPolicy,
    AutoAddPolicy,
    RejectPolicy,
    WarningPolicy,
)
from paramiko.auth_handler import AuthHandler
from paramiko.auth_strategy import (
    AuthFailure,
    AuthStrategy,
    AuthResult,
    AuthSource,
    InMemoryPrivateKey,
    NoneAuth,
    OnDiskPrivateKey,
    Password,
    PrivateKey,
    SourceResult,
)
from paramiko.ssh_gss import GSSAuth, GSS_AUTH_AVAILABLE, GSS_EXCEPTIONS
from paramiko.channel import (
    Channel,
    ChannelFile,
    ChannelStderrFile,
    ChannelStdinFile,
)
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    BadHostKeyException,
    ChannelException,
    ConfigParseError,
    CouldNotCanonicalize,
    IncompatiblePeer,
    PasswordRequiredException,
    ProxyCommandFailure,
    SSHException,
)
from paramiko.server import ServerInterface, SubsystemHandler, InteractiveQuery
from paramiko.rsakey import RSAKey
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.sftp import SFTPError, BaseSFTP
from paramiko.sftp_client import SFTP, SFTPClient
from paramiko.sftp_server import SFTPServer
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_si import SFTPServerInterface
from paramiko.sftp_file import SFTPFile
from paramiko.message import Message
from paramiko.packet import Packetizer
from paramiko.file import BufferedFile
from paramiko.agent import Agent, AgentKey
from paramiko.pkey import PKey, PublicBlob, UnknownKeyType
from paramiko.hostkeys import HostKeys
from paramiko.config import SSHConfig, SSHConfigDict
from paramiko.proxy import ProxyCommand

from paramiko.common import (
    AUTH_SUCCESSFUL,
    AUTH_PARTIALLY_SUCCESSFUL,
    AUTH_FAILED,
    OPEN_SUCCEEDED,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_FAILED_CONNECT_FAILED,
    OPEN_FAILED_UNKNOWN_CHANNEL_TYPE,
    OPEN_FAILED_RESOURCE_SHORTAGE,
)

from paramiko.sftp import (
    SFTP_OK,
    SFTP_EOF,
    SFTP_NO_SUCH_FILE,
    SFTP_PERMISSION_DENIED,
    SFTP_FAILURE,
    SFTP_BAD_MESSAGE,
    SFTP_NO_CONNECTION,
    SFTP_CONNECTION_LOST,
    SFTP_OP_UNSUPPORTED,
)

from paramiko.common import io_sleep


# TODO: I guess a real plugin system might be nice for future expansion...
key_classes = [DSSKey, RSAKey, Ed25519Key, ECDSAKey]


__author__ = "Jeff Forcier <jeff@bitprophet.org>"
__license__ = "GNU Lesser General Public License (LGPL)"

# TODO 4.0: remove this, jeez
__all__ = [
    "Agent",
    "AgentKey",
    "AuthenticationException",
    "AutoAddPolicy",
    "BadAuthenticationType",
    "BadHostKeyException",
    "BufferedFile",
    "Channel",
    "ChannelException",
    "ConfigParseError",
    "CouldNotCanonicalize",
    "DSSKey",
    "ECDSAKey",
    "Ed25519Key",
    "HostKeys",
    "Message",
    "MissingHostKeyPolicy",
    "PKey",
    "PasswordRequiredException",
    "ProxyCommand",
    "ProxyCommandFailure",
    "RSAKey",
    "RejectPolicy",
    "SFTP",
    "SFTPAttributes",
    "SFTPClient",
    "SFTPError",
    "SFTPFile",
    "SFTPHandle",
    "SFTPServer",
    "SFTPServerInterface",
    "SSHClient",
    "SSHConfig",
    "SSHConfigDict",
    "SSHException",
    "SecurityOptions",
    "ServerInterface",
    "SubsystemHandler",
    "Transport",
    "WarningPolicy",
    "io_sleep",
    "util",
]
