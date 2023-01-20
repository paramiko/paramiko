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


class SSHException(Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """

    pass


class AuthenticationException(SSHException):
    """
    Exception raised when authentication failed for some reason.  It may be
    possible to retry with different credentials.  (Other classes specify more
    specific reasons.)

    .. versionadded:: 1.6
    """

    pass


class PasswordRequiredException(AuthenticationException):
    """
    Exception raised when a password is needed to unlock a private key file.
    """

    pass


class BadAuthenticationType(AuthenticationException):
    """
    Exception raised when an authentication type (like password) is used, but
    the server isn't allowing that type.  (It may only allow public-key, for
    example.)

    .. versionadded:: 1.1
    """

    allowed_types = []

    # TODO 4.0: remove explanation kwarg
    def __init__(self, explanation, types):
        # TODO 4.0: remove this supercall unless it's actually required for
        # pickling (after fixing pickling)
        AuthenticationException.__init__(self, explanation, types)
        self.explanation = explanation
        self.allowed_types = types

    def __str__(self):
        return "{}; allowed types: {!r}".format(
            self.explanation, self.allowed_types
        )


class PartialAuthentication(AuthenticationException):
    """
    An internal exception thrown in the case of partial authentication.
    """

    allowed_types = []

    def __init__(self, types):
        AuthenticationException.__init__(self, types)
        self.allowed_types = types

    def __str__(self):
        return "Partial authentication; allowed types: {!r}".format(
            self.allowed_types
        )


class ChannelException(SSHException):
    """
    Exception raised when an attempt to open a new `.Channel` fails.

    :param int code: the error code returned by the server

    .. versionadded:: 1.6
    """

    def __init__(self, code, text):
        SSHException.__init__(self, code, text)
        self.code = code
        self.text = text

    def __str__(self):
        return "ChannelException({!r}, {!r})".format(self.code, self.text)


class BadHostKeyException(SSHException):
    """
    The host key given by the SSH server did not match what we were expecting.

    :param str hostname: the hostname of the SSH server
    :param PKey got_key: the host key presented by the server
    :param PKey expected_key: the host key expected

    .. versionadded:: 1.6
    """

    def __init__(self, hostname, got_key, expected_key):
        SSHException.__init__(self, hostname, got_key, expected_key)
        self.hostname = hostname
        self.key = got_key
        self.expected_key = expected_key

    def __str__(self):
        msg = "Host key for server '{}' does not match: got '{}', expected '{}'"  # noqa
        return msg.format(
            self.hostname,
            self.key.get_base64(),
            self.expected_key.get_base64(),
        )


class IncompatiblePeer(SSHException):
    """
    A disagreement arose regarding an algorithm required for key exchange.

    .. versionadded:: 2.9
    """

    # TODO 4.0: consider making this annotate w/ 1..N 'missing' algorithms,
    # either just the first one that would halt kex, or even updating the
    # Transport logic so we record /all/ that /could/ halt kex.
    # TODO: update docstrings where this may end up raised so they are more
    # specific.
    pass


class ProxyCommandFailure(SSHException):
    """
    The "ProxyCommand" found in the .ssh/config file returned an error.

    :param str command: The command line that is generating this exception.
    :param str error: The error captured from the proxy command output.
    """

    def __init__(self, command, error):
        SSHException.__init__(self, command, error)
        self.command = command
        self.error = error

    def __str__(self):
        return 'ProxyCommand("{}") returned nonzero exit status: {}'.format(
            self.command, self.error
        )


class CouldNotCanonicalize(SSHException):
    """
    Raised when hostname canonicalization fails & fallback is disabled.

    .. versionadded:: 2.7
    """

    pass


class ConfigParseError(SSHException):
    """
    A fatal error was encountered trying to parse SSH config data.

    Typically this means a config file violated the ``ssh_config``
    specification in a manner that requires exiting immediately, such as not
    matching ``key = value`` syntax or misusing certain ``Match`` keywords.

    .. versionadded:: 2.7
    """

    pass
