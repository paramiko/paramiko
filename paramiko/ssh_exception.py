#!/usr/bin/python

"""
Exceptions defined by paramiko.
"""


class SSHException (Exception):
    """
    Exception thrown by failures in SSH2 protocol negotiation or logic errors.
    """
    pass

class PasswordRequiredException (SSHException):
    """
    Exception thrown when a password is needed to unlock a private key file.
    """
    pass
