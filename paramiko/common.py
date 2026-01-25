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
Common constants and global variables.
"""
import logging
import struct
from typing import Final

MSG_DISCONNECT: Final
MSG_IGNORE: Final
MSG_UNIMPLEMENTED: Final
MSG_DEBUG: Final
MSG_SERVICE_REQUEST: Final
MSG_SERVICE_ACCEPT: Final
MSG_EXT_INFO: Final
MSG_KEXINIT: Final
MSG_NEWKEYS: Final
MSG_USERAUTH_REQUEST: Final
MSG_USERAUTH_FAILURE: Final
MSG_USERAUTH_SUCCESS: Final
MSG_USERAUTH_BANNER: Final
MSG_USERAUTH_INFO_REQUEST: Final
MSG_USERAUTH_INFO_RESPONSE: Final
MSG_USERAUTH_GSSAPI_RESPONSE: Final
MSG_USERAUTH_GSSAPI_TOKEN: Final
MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: Final
MSG_USERAUTH_GSSAPI_ERROR: Final
MSG_USERAUTH_GSSAPI_ERRTOK: Final
MSG_USERAUTH_GSSAPI_MIC: Final
MSG_GLOBAL_REQUEST: Final
MSG_REQUEST_SUCCESS: Final
MSG_REQUEST_FAILURE: Final
MSG_CHANNEL_OPEN: Final
MSG_CHANNEL_OPEN_SUCCESS: Final
MSG_CHANNEL_OPEN_FAILURE: Final
MSG_CHANNEL_WINDOW_ADJUST: Final
MSG_CHANNEL_DATA: Final
MSG_CHANNEL_EXTENDED_DATA: Final
MSG_CHANNEL_EOF: Final
MSG_CHANNEL_CLOSE: Final
MSG_CHANNEL_REQUEST: Final
MSG_CHANNEL_SUCCESS: Final
MSG_CHANNEL_FAILURE: Final
AUTH_SUCCESSFUL: Final
AUTH_PARTIALLY_SUCCESSFUL: Final
AUTH_FAILED: Final
OPEN_SUCCEEDED: Final
OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED: Final
OPEN_FAILED_CONNECT_FAILED: Final
OPEN_FAILED_UNKNOWN_CHANNEL_TYPE: Final
OPEN_FAILED_RESOURCE_SHORTAGE: Final
DISCONNECT_SERVICE_NOT_AVAILABLE: Final
DISCONNECT_AUTH_CANCELLED_BY_USER: Final
DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: Final

#
# Formerly of py3compat.py. May be fully delete'able with a deeper look?
#


def byte_chr(c: int) -> bytes:
    assert isinstance(c, int)
    return struct.pack("B", c)


def byte_mask(c: int, mask: int) -> bytes:
    assert isinstance(c, int)
    return struct.pack("B", c & mask)


def byte_ord(c: int | str) -> int:
    # In case we're handed a string instead of an int.
    if not isinstance(c, int):
        c = ord(c)
    return c


(
    MSG_DISCONNECT,
    MSG_IGNORE,
    MSG_UNIMPLEMENTED,
    MSG_DEBUG,
    MSG_SERVICE_REQUEST,
    MSG_SERVICE_ACCEPT,
    MSG_EXT_INFO,
) = range(1, 8)
(MSG_KEXINIT, MSG_NEWKEYS) = range(20, 22)
(
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_SUCCESS,
    MSG_USERAUTH_BANNER,
) = range(50, 54)
MSG_USERAUTH_PK_OK: Final = 60
(MSG_USERAUTH_INFO_REQUEST, MSG_USERAUTH_INFO_RESPONSE) = range(60, 62)
(MSG_USERAUTH_GSSAPI_RESPONSE, MSG_USERAUTH_GSSAPI_TOKEN) = range(60, 62)
(
    MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
    MSG_USERAUTH_GSSAPI_ERROR,
    MSG_USERAUTH_GSSAPI_ERRTOK,
    MSG_USERAUTH_GSSAPI_MIC,
) = range(63, 67)
HIGHEST_USERAUTH_MESSAGE_ID: Final = 79
(MSG_GLOBAL_REQUEST, MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE) = range(80, 83)
(
    MSG_CHANNEL_OPEN,
    MSG_CHANNEL_OPEN_SUCCESS,
    MSG_CHANNEL_OPEN_FAILURE,
    MSG_CHANNEL_WINDOW_ADJUST,
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_EXTENDED_DATA,
    MSG_CHANNEL_EOF,
    MSG_CHANNEL_CLOSE,
    MSG_CHANNEL_REQUEST,
    MSG_CHANNEL_SUCCESS,
    MSG_CHANNEL_FAILURE,
) = range(90, 101)

cMSG_DISCONNECT: Final[bytes] = byte_chr(MSG_DISCONNECT)
cMSG_IGNORE: Final[bytes] = byte_chr(MSG_IGNORE)
cMSG_UNIMPLEMENTED: Final[bytes] = byte_chr(MSG_UNIMPLEMENTED)
cMSG_DEBUG: Final[bytes] = byte_chr(MSG_DEBUG)
cMSG_SERVICE_REQUEST: Final[bytes] = byte_chr(MSG_SERVICE_REQUEST)
cMSG_SERVICE_ACCEPT: Final[bytes] = byte_chr(MSG_SERVICE_ACCEPT)
cMSG_EXT_INFO: Final[bytes] = byte_chr(MSG_EXT_INFO)
cMSG_KEXINIT: Final[bytes] = byte_chr(MSG_KEXINIT)
cMSG_NEWKEYS: Final[bytes] = byte_chr(MSG_NEWKEYS)
cMSG_USERAUTH_REQUEST: Final[bytes] = byte_chr(MSG_USERAUTH_REQUEST)
cMSG_USERAUTH_FAILURE: Final[bytes] = byte_chr(MSG_USERAUTH_FAILURE)
cMSG_USERAUTH_SUCCESS: Final[bytes] = byte_chr(MSG_USERAUTH_SUCCESS)
cMSG_USERAUTH_BANNER: Final[bytes] = byte_chr(MSG_USERAUTH_BANNER)
cMSG_USERAUTH_PK_OK: Final[bytes] = byte_chr(MSG_USERAUTH_PK_OK)
cMSG_USERAUTH_INFO_REQUEST: Final[bytes] = byte_chr(MSG_USERAUTH_INFO_REQUEST)
cMSG_USERAUTH_INFO_RESPONSE: Final[bytes] = byte_chr(
    MSG_USERAUTH_INFO_RESPONSE
)
cMSG_USERAUTH_GSSAPI_RESPONSE: Final[bytes] = byte_chr(
    MSG_USERAUTH_GSSAPI_RESPONSE
)
cMSG_USERAUTH_GSSAPI_TOKEN: Final[bytes] = byte_chr(MSG_USERAUTH_GSSAPI_TOKEN)
cMSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: Final[bytes] = byte_chr(
    MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE
)
cMSG_USERAUTH_GSSAPI_ERROR: Final[bytes] = byte_chr(MSG_USERAUTH_GSSAPI_ERROR)
cMSG_USERAUTH_GSSAPI_ERRTOK: Final[bytes] = byte_chr(
    MSG_USERAUTH_GSSAPI_ERRTOK
)
cMSG_USERAUTH_GSSAPI_MIC: Final[bytes] = byte_chr(MSG_USERAUTH_GSSAPI_MIC)
cMSG_GLOBAL_REQUEST: Final[bytes] = byte_chr(MSG_GLOBAL_REQUEST)
cMSG_REQUEST_SUCCESS: Final[bytes] = byte_chr(MSG_REQUEST_SUCCESS)
cMSG_REQUEST_FAILURE: Final[bytes] = byte_chr(MSG_REQUEST_FAILURE)
cMSG_CHANNEL_OPEN: Final[bytes] = byte_chr(MSG_CHANNEL_OPEN)
cMSG_CHANNEL_OPEN_SUCCESS: Final[bytes] = byte_chr(MSG_CHANNEL_OPEN_SUCCESS)
cMSG_CHANNEL_OPEN_FAILURE: Final[bytes] = byte_chr(MSG_CHANNEL_OPEN_FAILURE)
cMSG_CHANNEL_WINDOW_ADJUST: Final[bytes] = byte_chr(MSG_CHANNEL_WINDOW_ADJUST)
cMSG_CHANNEL_DATA: Final[bytes] = byte_chr(MSG_CHANNEL_DATA)
cMSG_CHANNEL_EXTENDED_DATA: Final[bytes] = byte_chr(MSG_CHANNEL_EXTENDED_DATA)
cMSG_CHANNEL_EOF: Final[bytes] = byte_chr(MSG_CHANNEL_EOF)
cMSG_CHANNEL_CLOSE: Final[bytes] = byte_chr(MSG_CHANNEL_CLOSE)
cMSG_CHANNEL_REQUEST: Final[bytes] = byte_chr(MSG_CHANNEL_REQUEST)
cMSG_CHANNEL_SUCCESS: Final[bytes] = byte_chr(MSG_CHANNEL_SUCCESS)
cMSG_CHANNEL_FAILURE: Final[bytes] = byte_chr(MSG_CHANNEL_FAILURE)

# for debugging:
MSG_NAMES: dict[int, str] = {
    MSG_DISCONNECT: "disconnect",
    MSG_IGNORE: "ignore",
    MSG_UNIMPLEMENTED: "unimplemented",
    MSG_DEBUG: "debug",
    MSG_SERVICE_REQUEST: "service-request",
    MSG_SERVICE_ACCEPT: "service-accept",
    MSG_KEXINIT: "kexinit",
    MSG_EXT_INFO: "ext-info",
    MSG_NEWKEYS: "newkeys",
    30: "kex30",
    31: "kex31",
    32: "kex32",
    33: "kex33",
    34: "kex34",
    40: "kex40",
    41: "kex41",
    MSG_USERAUTH_REQUEST: "userauth-request",
    MSG_USERAUTH_FAILURE: "userauth-failure",
    MSG_USERAUTH_SUCCESS: "userauth-success",
    MSG_USERAUTH_BANNER: "userauth--banner",
    MSG_USERAUTH_PK_OK: "userauth-60(pk-ok/info-request)",
    MSG_USERAUTH_INFO_RESPONSE: "userauth-info-response",
    MSG_GLOBAL_REQUEST: "global-request",
    MSG_REQUEST_SUCCESS: "request-success",
    MSG_REQUEST_FAILURE: "request-failure",
    MSG_CHANNEL_OPEN: "channel-open",
    MSG_CHANNEL_OPEN_SUCCESS: "channel-open-success",
    MSG_CHANNEL_OPEN_FAILURE: "channel-open-failure",
    MSG_CHANNEL_WINDOW_ADJUST: "channel-window-adjust",
    MSG_CHANNEL_DATA: "channel-data",
    MSG_CHANNEL_EXTENDED_DATA: "channel-extended-data",
    MSG_CHANNEL_EOF: "channel-eof",
    MSG_CHANNEL_CLOSE: "channel-close",
    MSG_CHANNEL_REQUEST: "channel-request",
    MSG_CHANNEL_SUCCESS: "channel-success",
    MSG_CHANNEL_FAILURE: "channel-failure",
    MSG_USERAUTH_GSSAPI_RESPONSE: "userauth-gssapi-response",
    MSG_USERAUTH_GSSAPI_TOKEN: "userauth-gssapi-token",
    MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: "userauth-gssapi-exchange-complete",
    MSG_USERAUTH_GSSAPI_ERROR: "userauth-gssapi-error",
    MSG_USERAUTH_GSSAPI_ERRTOK: "userauth-gssapi-error-token",
    MSG_USERAUTH_GSSAPI_MIC: "userauth-gssapi-mic",
}


# authentication request return codes:
AUTH_SUCCESSFUL, AUTH_PARTIALLY_SUCCESSFUL, AUTH_FAILED = range(3)


# channel request failed reasons:
(
    OPEN_SUCCEEDED,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_FAILED_CONNECT_FAILED,
    OPEN_FAILED_UNKNOWN_CHANNEL_TYPE,
    OPEN_FAILED_RESOURCE_SHORTAGE,
) = range(0, 5)


CONNECTION_FAILED_CODE: dict[int, str] = {
    1: "Administratively prohibited",
    2: "Connect failed",
    3: "Unknown channel type",
    4: "Resource shortage",
}


(
    DISCONNECT_SERVICE_NOT_AVAILABLE,
    DISCONNECT_AUTH_CANCELLED_BY_USER,
    DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
) = (7, 13, 14)

zero_byte: bytes = byte_chr(0)
one_byte: bytes = byte_chr(1)
four_byte: bytes = byte_chr(4)
max_byte: bytes = byte_chr(0xFF)
cr_byte: bytes = byte_chr(13)
linefeed_byte: bytes = byte_chr(10)
crlf: bytes = cr_byte + linefeed_byte
cr_byte_value = 13
linefeed_byte_value = 10


xffffffff = 0xFFFFFFFF
x80000000 = 0x80000000
o666 = 438
o660 = 432
o644 = 420
o600 = 384
o777 = 511
o700 = 448
o70 = 56

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

# Common IO/select/etc sleep period, in seconds
io_sleep = 0.01

DEFAULT_WINDOW_SIZE: Final[int] = 64 * 2**15
DEFAULT_MAX_PACKET_SIZE: Final[int] = 2**15

# lower bound on the max packet size we'll accept from the remote host
# Minimum packet size is 32768 bytes according to
# http://www.ietf.org/rfc/rfc4254.txt
MIN_WINDOW_SIZE: Final[int] = 2**15

# However, according to http://www.ietf.org/rfc/rfc4253.txt it is perfectly
# legal to accept a size much smaller, as OpenSSH client does as size 16384.
MIN_PACKET_SIZE: Final[int] = 2**12

# Max windows size according to http://www.ietf.org/rfc/rfc4254.txt
MAX_WINDOW_SIZE: Final[int] = 2**32 - 1
