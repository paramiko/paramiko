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
L{ServerInterface} is an interface to override for server support.
"""

from auth_transport import Transport

class ServerInterface (object):
    """
    This class defines an interface for controlling the behavior of paramiko
    in server mode.
    """

    def check_channel_request(self, kind, chanid):
        """
        Determine if a channel request of a given type will be granted, and
        return a suitable L{Channel} object.  This method is called in server
        mode when the client requests a channel, after authentication is
        complete.

        You will generally want to subclass L{Channel} to override some of the
        methods for handling client requests (such as connecting to a subsystem
        opening a shell) to determine what you want to allow or disallow.  For
        this reason, L{check_channel_request} must return a new object of that
        type.  The C{chanid} parameter is passed so that you can use it in
        L{Channel}'s constructor.

        The default implementation always returns C{None}, rejecting any
        channel requests.  A useful server must override this method.

        @param kind: the kind of channel the client would like to open
        (usually C{"session"}).
        @type kind: string
        @param chanid: ID of the channel, required to create a new L{Channel}
        object.
        @type chanid: int
        @return: a new L{Channel} object (or subclass thereof), or C{None} to
        refuse the request.
        @rtype: L{Channel}
        """
        return None

    def get_allowed_auths(self, username):
        """
        Return a list of authentication methods supported by the server.
        This list is sent to clients attempting to authenticate, to inform them
        of authentication methods that might be successful.

        The "list" is actually a string of comma-separated names of types of
        authentication.  Possible values are C{"password"}, C{"publickey"},
        and C{"none"}.

        The default implementation always returns C{"password"}.

        @param username: the username requesting authentication.
        @type username: string
        @return: a comma-separated list of authentication types
        @rtype: string
        """
        return 'password'

    def check_auth_none(self, username):
        """
        Determine if a client may open channels with no (further)
        authentication.

        Return L{Transport.AUTH_FAILED} if the client must authenticate, or
        L{Transport.AUTH_SUCCESSFUL} if it's okay for the client to not
        authenticate.

        The default implementation always returns L{Transport.AUTH_FAILED}.

        @param username: the username of the client.
        @type username: string
        @return: L{Transport.AUTH_FAILED} if the authentication fails;
        L{Transport.AUTH_SUCCESSFUL} if it succeeds.
        @rtype: int
        """
        return Transport.AUTH_FAILED

    def check_auth_password(self, username, password):
        """
        Determine if a given username and password supplied by the client is
        acceptable for use in authentication.

        Return L{Transport.AUTH_FAILED} if the password is not accepted,
        L{Transport.AUTH_SUCCESSFUL} if the password is accepted and completes
        the authentication, or L{Transport.AUTH_PARTIALLY_SUCCESSFUL} if your
        authentication is stateful, and this key is accepted for
        authentication, but more authentication is required.  (In this latter
        case, L{get_allowed_auths} will be called to report to the client what
        options it has for continuing the authentication.)

        The default implementation always returns L{Transport.AUTH_FAILED}.

        @param username: the username of the authenticating client.
        @type username: string
        @param password: the password given by the client.
        @type password: string
        @return: L{Transport.AUTH_FAILED} if the authentication fails;
        L{Transport.AUTH_SUCCESSFUL} if it succeeds;
        L{Transport.AUTH_PARTIALLY_SUCCESSFUL} if the password auth is
        successful, but authentication must continue.
        @rtype: int
        """
        return Transport.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """
        Determine if a given key supplied by the client is acceptable for use
        in authentication.  You should override this method in server mode to
        check the username and key and decide if you would accept a signature
        made using this key.

        Return L{Transport.AUTH_FAILED} if the key is not accepted,
        L{Transport.AUTH_SUCCESSFUL} if the key is accepted and completes the
        authentication, or L{Transport.AUTH_PARTIALLY_SUCCESSFUL} if your
        authentication is stateful, and this key is accepted for
        authentication, but more authentication is required.  (In this latter
        case, L{get_allowed_auths} will be called to report to the client what
        options it has for continuing the authentication.)

        The default implementation always returns L{Transport.AUTH_FAILED}.

        @param username: the username of the authenticating client.
        @type username: string
        @param key: the key object provided by the client.
        @type key: L{PKey <pkey.PKey>}
        @return: L{Transport.AUTH_FAILED} if the client can't authenticate
        with this key; L{Transport.AUTH_SUCCESSFUL} if it can;
        L{Transport.AUTH_PARTIALLY_SUCCESSFUL} if it can authenticate with
        this key but must continue with authentication.
        @rtype: int
        """
        return Transport.AUTH_FAILED
