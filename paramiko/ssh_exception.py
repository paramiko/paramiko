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
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Exceptions defined by paramiko.
"""


class SSHException (Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """
    pass

class PasswordRequiredException (SSHException):
    """
    Exception raised when a password is needed to unlock a private key file.
    """
    pass

class BadAuthenticationType (SSHException):
    """
    Exception raised when an authentication type (like password) is used, but
    the server isn't allowing that type.  (It may only allow public-key, for
    example.)
    
    @ivar allowed_types: list of allowed authentication types provided by the
        server (possible values are: C{"none"}, C{"password"}, and
        C{"publickey"}).
    @type allowed_types: list
    
    @since: 1.1
    """
    allowed_types = []
    
    def __init__(self, explanation, types):
        SSHException.__init__(self, explanation)
        self.allowed_types = types
