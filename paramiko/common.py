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
Common constants and global variables.
"""

MSG_DISCONNECT, MSG_IGNORE, MSG_UNIMPLEMENTED, MSG_DEBUG, MSG_SERVICE_REQUEST, \
	MSG_SERVICE_ACCEPT = range(1, 7)
MSG_KEXINIT, MSG_NEWKEYS = range(20, 22)
MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE, MSG_USERAUTH_SUCCESS, \
        MSG_USERAUTH_BANNER = range(50, 54)
MSG_USERAUTH_PK_OK = 60
MSG_GLOBAL_REQUEST, MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE = range(80, 83)
MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_SUCCESS, MSG_CHANNEL_OPEN_FAILURE, \
	MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA, \
	MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE, MSG_CHANNEL_REQUEST, \
	MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE = range(90, 101)


# channel request failed reasons:
CONNECTION_FAILED_CODE = {
    1: 'Administratively prohibited',
    2: 'Connect failed',
    3: 'Unknown channel type',
    4: 'Resource shortage'
}

DISCONNECT_SERVICE_NOT_AVAILABLE, DISCONNECT_AUTH_CANCELLED_BY_USER, \
    DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 7, 13, 14



from Crypto.Util.randpool import PersistentRandomPool, RandomPool

# keep a crypto-strong PRNG nearby
try:
    randpool = PersistentRandomPool(os.getenv('HOME') + '/.randpool')
except:
    # the above will likely fail on Windows - fall back to non-persistent random pool
    randpool = RandomPool()

randpool.randomize()


import sys
if sys.version_info < (2, 3):
    try:
        import logging
    except:
        import logging22 as logging
    import select
    PY22 = True

    import socket
    if not hasattr(socket, 'timeout'):
        class timeout(socket.error): pass
        socket.timeout = timeout
        del timeout
else:
    import logging
    PY22 = False

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL
