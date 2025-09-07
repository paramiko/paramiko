# Copyright (C) 2013-2014 science + computing ag
# Author: Sebastian Deiss <sebastian.deiss@t-online.de>
#
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
This module provides GSS-API / SSPI  authentication as defined in :rfc:`4462`.

.. note:: Credential delegation is not supported in server mode.

.. seealso:: :doc:`/api/kex_gss`

.. versionadded:: 1.15
"""

import struct
import os
import sys


#: A boolean constraint that indicates if GSS-API / SSPI is available.
GSS_AUTH_AVAILABLE = True


#: A tuple of the exception types used by the underlying GSSAPI implementation.
GSS_EXCEPTIONS = ()


#: :var str _API: Constraint for the used API
_API = None

try:
    import gssapi

    if hasattr(gssapi, "__title__") and gssapi.__title__ == "python-gssapi":
        # old, unmaintained python-gssapi package
        _API = "MIT"  # keep this for compatibility
        GSS_EXCEPTIONS = (gssapi.GSSException,)
    else:
        _API = "PYTHON-GSSAPI-NEW"
        GSS_EXCEPTIONS = (
            gssapi.exceptions.GeneralError,
            gssapi.raw.misc.GSSError,
        )
except (ImportError, OSError):
    try:
        import pywintypes
        import sspicon
        import sspi

        _API = "SSPI"
        GSS_EXCEPTIONS = (pywintypes.error,)
    except ImportError:
        GSS_AUTH_AVAILABLE = False
        _API = None

from paramiko.common import MSG_USERAUTH_REQUEST
from paramiko.ssh_exception import SSHException


def GSSAuth(auth_method, gss_deleg_creds=True):
    """
    Provide SSH2 GSS-API / SSPI authentication.

    :param str auth_method: The name of the SSH authentication mechanism
                            (gssapi-with-mic or gss-keyex)
    :param bool gss_deleg_creds: Delegate client credentials or not.
                                 We delegate credentials by default.
    :return: Either an `._SSH_GSSAPI_OLD` or `._SSH_GSSAPI_NEW` (Unix)
             object or an `_SSH_SSPI` (Windows) object
    :rtype: object

    :raises: ``ImportError`` -- If no GSS-API / SSPI module could be imported.

    :see: `RFC 4462 <http://www.ietf.org/rfc/rfc4462.txt>`_
    :note: Check for the available API and return either an `._SSH_GSSAPI_OLD`
           (MIT GSSAPI using python-gssapi package) object, an
           `._SSH_GSSAPI_NEW` (MIT GSSAPI using gssapi package) object
           or an `._SSH_SSPI` (MS SSPI) object.
           If there is no supported API available,
           ``None`` will be returned.
    """
    if _API == "MIT":
        return _SSH_GSSAPI_OLD(auth_method, gss_deleg_creds)
    elif _API == "PYTHON-GSSAPI-NEW":
        return _SSH_GSSAPI_NEW(auth_method, gss_deleg_creds)
    elif _API == "SSPI" and os.name == "nt":
        return _SSH_SSPI(auth_method, gss_deleg_creds)
    else:
        raise ImportError("Unable to import a GSS-API / SSPI module!")


class _SSH_GSSAuth:
    """
    Contains the shared variables and methods of `._SSH_GSSAPI_OLD`,
    `._SSH_GSSAPI_NEW` and `._SSH_SSPI`.
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        self._auth_method = auth_method
        self._gss_deleg_creds = gss_deleg_creds
        self._gss_host = None
        self._username = None
        self._session_id = None
        self._service = "ssh-connection"
        """
        OpenSSH supports Kerberos V5 mechanism only for GSS-API authentication,
        so we also support the krb5 mechanism only.
        """
        self._krb5_mech = "1.2.840.113554.1.2.2"

        # client mode
        self._gss_ctxt = None
        self._gss_ctxt_status = False

        # server mode
        self._gss_srv_ctxt = None
        self._gss_srv_ctxt_status = False
        self.cc_file = None

    def set_service(self, service):
        """
        This is just a setter to use a non default service.
        I added this method, because RFC 4462 doesn't specify "ssh-connection"
        as the only service value.

        :param str service: The desired SSH service
        """
        if service.find("ssh-"):
            self._service = service

    def set_username(self, username):
        """
        Setter for C{username}. If GSS-API Key Exchange is performed, the
        username is not set by C{ssh_init_sec_context}.

        :param str username: The name of the user who attempts to login
        """
        self._username = username

    def ssh_gss_oids(self, mode="client"):
        """
        This method returns a single OID, because we only support the
        Kerberos V5 mechanism.

        :param str mode: Client for client mode and server for server mode
        :return: A byte sequence containing the number of supported
                 OIDs, the length of the OID and the actual OID encoded with
                 DER
        :note: In server mode we just return the OID length and the DER encoded
               OID.
        """
        from pyasn1.type.univ import ObjectIdentifier
        from pyasn1.codec.der import encoder

        OIDs = self._make_uint32(1)
        krb5_OID = encoder.encode(ObjectIdentifier(self._krb5_mech))
        OID_len = self._make_uint32(len(krb5_OID))
        if mode == "server":
            return OID_len + krb5_OID
        return OIDs + OID_len + krb5_OID

    def ssh_check_mech(self, desired_mech):
        """
        Check if the given OID is the Kerberos V5 OID (server mode).

        :param str desired_mech: The desired GSS-API mechanism of the client
        :return: ``True`` if the given OID is supported, otherwise C{False}
        """
        from pyasn1.codec.der import decoder

        mech, __ = decoder.decode(desired_mech)
        if mech.__str__() != self._krb5_mech:
            return False
        return True

    # Internals
    # -------------------------------------------------------------------------
    def _make_uint32(self, integer):
        """
        Create a 32 bit unsigned integer (The byte sequence of an integer).

        :param int integer: The integer value to convert
        :return: The byte sequence of an 32 bit integer
        """
        return struct.pack("!I", integer)

    def _ssh_build_mic(self, session_id, username, service, auth_method):
        """
        Create the SSH2 MIC filed for gssapi-with-mic.

        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :param str service: The requested SSH service
        :param str auth_method: The requested SSH authentication mechanism
        :return: The MIC as defined in RFC 4462. The contents of the
                 MIC field are:
                 string    session_identifier,
                 byte      SSH_MSG_USERAUTH_REQUEST,
                 string    user-name,
                 string    service (ssh-connection),
                 string    authentication-method
                           (gssapi-with-mic or gssapi-keyex)
        """
        mic = self._make_uint32(len(session_id))
        mic += session_id
        mic += struct.pack("B", MSG_USERAUTH_REQUEST)
        mic += self._make_uint32(len(username))
        mic += username.encode()
        mic += self._make_uint32(len(service))
        mic += service.encode()
        mic += self._make_uint32(len(auth_method))
        mic += auth_method.encode()
        return mic


class _SSH_GSSAPI_OLD(_SSH_GSSAuth):
    """
    Implementation of the GSS-API MIT Kerberos Authentication for SSH2,
    using the older (unmaintained) python-gssapi package.

    :see: `.GSSAuth`
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        _SSH_GSSAuth.__init__(self, auth_method, gss_deleg_creds)

        if self._gss_deleg_creds:
            self._gss_flags = (
                gssapi.C_PROT_READY_FLAG,
                gssapi.C_INTEG_FLAG,
                gssapi.C_MUTUAL_FLAG,
                gssapi.C_DELEG_FLAG,
            )
        else:
            self._gss_flags = (
                gssapi.C_PROT_READY_FLAG,
                gssapi.C_INTEG_FLAG,
                gssapi.C_MUTUAL_FLAG,
            )

    def ssh_init_sec_context(
        self, target, desired_mech=None, username=None, recv_token=None
    ):
        """
        Initialize a GSS-API context.

        :param str username: The name of the user who attempts to login
        :param str target: The hostname of the target to connect to
        :param str desired_mech: The negotiated GSS-API mechanism
                                 ("pseudo negotiated" mechanism, because we
                                 support just the krb5 mechanism :-))
        :param str recv_token: The GSS-API token received from the Server
        :raises:
            `.SSHException` -- Is raised if the desired mechanism of the client
            is not supported
        :return: A ``String`` if the GSS-API has returned a token or
            ``None`` if no token was returned
        """
        from pyasn1.codec.der import decoder

        self._username = username
        self._gss_host = target
        targ_name = gssapi.Name(
            "host@" + self._gss_host, gssapi.C_NT_HOSTBASED_SERVICE
        )
        ctx = gssapi.Context()
        ctx.flags = self._gss_flags
        if desired_mech is None:
            krb5_mech = gssapi.OID.mech_from_string(self._krb5_mech)
        else:
            mech, __ = decoder.decode(desired_mech)
            if mech.__str__() != self._krb5_mech:
                raise SSHException("Unsupported mechanism OID.")
            else:
                krb5_mech = gssapi.OID.mech_from_string(self._krb5_mech)
        token = None
        try:
            if recv_token is None:
                self._gss_ctxt = gssapi.InitContext(
                    peer_name=targ_name,
                    mech_type=krb5_mech,
                    req_flags=ctx.flags,
                )
                token = self._gss_ctxt.step(token)
            else:
                token = self._gss_ctxt.step(recv_token)
        except gssapi.GSSException:
            message = "{} Target: {}".format(sys.exc_info()[1], self._gss_host)
            raise gssapi.GSSException(message)
        self._gss_ctxt_status = self._gss_ctxt.established
        return token

    def ssh_get_mic(self, session_id, gss_kex=False):
        """
        Create the MIC token for a SSH2 message.

        :param str session_id: The SSH session ID
        :param bool gss_kex: Generate the MIC for GSS-API Key Exchange or not
        :return: gssapi-with-mic:
                 Returns the MIC token from GSS-API for the message we created
                 with ``_ssh_build_mic``.
                 gssapi-keyex:
                 Returns the MIC token from GSS-API with the SSH session ID as
                 message.
        """
        self._session_id = session_id
        if not gss_kex:
            mic_field = self._ssh_build_mic(
                self._session_id,
                self._username,
                self._service,
                self._auth_method,
            )
            mic_token = self._gss_ctxt.get_mic(mic_field)
        else:
            # for key exchange with gssapi-keyex
            mic_token = self._gss_srv_ctxt.get_mic(self._session_id)
        return mic_token

    def ssh_accept_sec_context(self, hostname, recv_token, username=None):
        """
        Accept a GSS-API context (server mode).

        :param str hostname: The servers hostname
        :param str username: The name of the user who attempts to login
        :param str recv_token: The GSS-API Token received from the server,
                               if it's not the initial call.
        :return: A ``String`` if the GSS-API has returned a token or ``None``
                if no token was returned
        """
        # hostname and username are not required for GSSAPI, but for SSPI
        self._gss_host = hostname
        self._username = username
        if self._gss_srv_ctxt is None:
            self._gss_srv_ctxt = gssapi.AcceptContext()
        token = self._gss_srv_ctxt.step(recv_token)
        self._gss_srv_ctxt_status = self._gss_srv_ctxt.established
        return token

    def ssh_check_mic(self, mic_token, session_id, username=None):
        """
        Verify the MIC token for a SSH2 message.

        :param str mic_token: The MIC token received from the client
        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :return: None if the MIC check was successful
        :raises: ``gssapi.GSSException`` -- if the MIC check failed
        """
        self._session_id = session_id
        self._username = username
        if self._username is not None:
            # server mode
            mic_field = self._ssh_build_mic(
                self._session_id,
                self._username,
                self._service,
                self._auth_method,
            )
            self._gss_srv_ctxt.verify_mic(mic_field, mic_token)
        else:
            # for key exchange with gssapi-keyex
            # client mode
            self._gss_ctxt.verify_mic(self._session_id, mic_token)

    @property
    def credentials_delegated(self):
        """
        Checks if credentials are delegated (server mode).

        :return: ``True`` if credentials are delegated, otherwise ``False``
        """
        if self._gss_srv_ctxt.delegated_cred is not None:
            return True
        return False

    def save_client_creds(self, client_token):
        """
        Save the Client token in a file. This is used by the SSH server
        to store the client credentials if credentials are delegated
        (server mode).

        :param str client_token: The GSS-API token received form the client
        :raises:
            ``NotImplementedError`` -- Credential delegation is currently not
            supported in server mode
        """
        raise NotImplementedError


class _SSH_GSSAPI_NEW(_SSH_GSSAuth):
    """
    Implementation of the GSS-API MIT Kerberos Authentication for SSH2,
    using the newer, currently maintained gssapi package.

    :see: `.GSSAuth`
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        _SSH_GSSAuth.__init__(self, auth_method, gss_deleg_creds)

        if self._gss_deleg_creds:
            self._gss_flags = (
                gssapi.RequirementFlag.protection_ready,
                gssapi.RequirementFlag.integrity,
                gssapi.RequirementFlag.mutual_authentication,
                gssapi.RequirementFlag.delegate_to_peer,
            )
        else:
            self._gss_flags = (
                gssapi.RequirementFlag.protection_ready,
                gssapi.RequirementFlag.integrity,
                gssapi.RequirementFlag.mutual_authentication,
            )

    def ssh_init_sec_context(
        self, target, desired_mech=None, username=None, recv_token=None
    ):
        """
        Initialize a GSS-API context.

        :param str username: The name of the user who attempts to login
        :param str target: The hostname of the target to connect to
        :param str desired_mech: The negotiated GSS-API mechanism
                                 ("pseudo negotiated" mechanism, because we
                                 support just the krb5 mechanism :-))
        :param str recv_token: The GSS-API token received from the Server
        :raises: `.SSHException` -- Is raised if the desired mechanism of the
                 client is not supported
        :raises: ``gssapi.exceptions.GSSError`` if there is an error signaled
                                                by the GSS-API implementation
        :return: A ``String`` if the GSS-API has returned a token or ``None``
                 if no token was returned
        """
        from pyasn1.codec.der import decoder

        self._username = username
        self._gss_host = target
        targ_name = gssapi.Name(
            "host@" + self._gss_host,
            name_type=gssapi.NameType.hostbased_service,
        )
        if desired_mech is not None:
            mech, __ = decoder.decode(desired_mech)
            if mech.__str__() != self._krb5_mech:
                raise SSHException("Unsupported mechanism OID.")
        krb5_mech = gssapi.MechType.kerberos
        token = None
        if recv_token is None:
            self._gss_ctxt = gssapi.SecurityContext(
                name=targ_name,
                flags=self._gss_flags,
                mech=krb5_mech,
                usage="initiate",
            )
            token = self._gss_ctxt.step(token)
        else:
            token = self._gss_ctxt.step(recv_token)
        self._gss_ctxt_status = self._gss_ctxt.complete
        return token

    def ssh_get_mic(self, session_id, gss_kex=False):
        """
        Create the MIC token for a SSH2 message.

        :param str session_id: The SSH session ID
        :param bool gss_kex: Generate the MIC for GSS-API Key Exchange or not
        :return: gssapi-with-mic:
                 Returns the MIC token from GSS-API for the message we created
                 with ``_ssh_build_mic``.
                 gssapi-keyex:
                 Returns the MIC token from GSS-API with the SSH session ID as
                 message.
        :rtype: str
        """
        self._session_id = session_id
        if not gss_kex:
            mic_field = self._ssh_build_mic(
                self._session_id,
                self._username,
                self._service,
                self._auth_method,
            )
            mic_token = self._gss_ctxt.get_signature(mic_field)
        else:
            # for key exchange with gssapi-keyex
            mic_token = self._gss_srv_ctxt.get_signature(self._session_id)
        return mic_token

    def ssh_accept_sec_context(self, hostname, recv_token, username=None):
        """
        Accept a GSS-API context (server mode).

        :param str hostname: The servers hostname
        :param str username: The name of the user who attempts to login
        :param str recv_token: The GSS-API Token received from the server,
                               if it's not the initial call.
        :return: A ``String`` if the GSS-API has returned a token or ``None``
                if no token was returned
        """
        # hostname and username are not required for GSSAPI, but for SSPI
        self._gss_host = hostname
        self._username = username
        if self._gss_srv_ctxt is None:
            self._gss_srv_ctxt = gssapi.SecurityContext(usage="accept")
        token = self._gss_srv_ctxt.step(recv_token)
        self._gss_srv_ctxt_status = self._gss_srv_ctxt.complete
        return token

    def ssh_check_mic(self, mic_token, session_id, username=None):
        """
        Verify the MIC token for a SSH2 message.

        :param str mic_token: The MIC token received from the client
        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :return: None if the MIC check was successful
        :raises: ``gssapi.exceptions.GSSError`` -- if the MIC check failed
        """
        self._session_id = session_id
        self._username = username
        if self._username is not None:
            # server mode
            mic_field = self._ssh_build_mic(
                self._session_id,
                self._username,
                self._service,
                self._auth_method,
            )
            self._gss_srv_ctxt.verify_signature(mic_field, mic_token)
        else:
            # for key exchange with gssapi-keyex
            # client mode
            self._gss_ctxt.verify_signature(self._session_id, mic_token)

    @property
    def credentials_delegated(self):
        """
        Checks if credentials are delegated (server mode).

        :return: ``True`` if credentials are delegated, otherwise ``False``
        :rtype: bool
        """
        if self._gss_srv_ctxt.delegated_creds is not None:
            return True
        return False

    def save_client_creds(self, client_token):
        """
        Save the Client token in a file. This is used by the SSH server
        to store the client credentials if credentials are delegated
        (server mode).

        :param str client_token: The GSS-API token received form the client
        :raises: ``NotImplementedError`` -- Credential delegation is currently
                 not supported in server mode
        """
        raise NotImplementedError


class _SSH_SSPI(_SSH_GSSAuth):
    """
    Implementation of the Microsoft SSPI Kerberos Authentication for SSH2.

    :see: `.GSSAuth`
    """

    def __init__(self, auth_method, gss_deleg_creds):
        """
        :param str auth_method: The name of the SSH authentication mechanism
                                (gssapi-with-mic or gss-keyex)
        :param bool gss_deleg_creds: Delegate client credentials or not
        """
        _SSH_GSSAuth.__init__(self, auth_method, gss_deleg_creds)

        if self._gss_deleg_creds:
            self._gss_flags = (
                sspicon.ISC_REQ_INTEGRITY
                | sspicon.ISC_REQ_MUTUAL_AUTH
                | sspicon.ISC_REQ_DELEGATE
            )
        else:
            self._gss_flags = (
                sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_MUTUAL_AUTH
            )

    def ssh_init_sec_context(
        self, target, desired_mech=None, username=None, recv_token=None
    ):
        """
        Initialize a SSPI context.

        :param str username: The name of the user who attempts to login
        :param str target: The FQDN of the target to connect to
        :param str desired_mech: The negotiated SSPI mechanism
                                 ("pseudo negotiated" mechanism, because we
                                 support just the krb5 mechanism :-))
        :param recv_token: The SSPI token received from the Server
        :raises:
            `.SSHException` -- Is raised if the desired mechanism of the client
            is not supported
        :return: A ``String`` if the SSPI has returned a token or ``None`` if
                 no token was returned
        """
        from pyasn1.codec.der import decoder

        self._username = username
        self._gss_host = target
        error = 0
        targ_name = "host/" + self._gss_host
        if desired_mech is not None:
            mech, __ = decoder.decode(desired_mech)
            if mech.__str__() != self._krb5_mech:
                raise SSHException("Unsupported mechanism OID.")
        try:
            if recv_token is None:
                self._gss_ctxt = sspi.ClientAuth(
                    "Kerberos", scflags=self._gss_flags, targetspn=targ_name
                )
            error, token = self._gss_ctxt.authorize(recv_token)
            token = token[0].Buffer
        except pywintypes.error as e:
            e.strerror += ", Target: {}".format(self._gss_host)
            raise

        if error == 0:
            """
            if the status is GSS_COMPLETE (error = 0) the context is fully
            established an we can set _gss_ctxt_status to True.
            """
            self._gss_ctxt_status = True
            token = None
            """
            You won't get another token if the context is fully established,
            so i set token to None instead of ""
            """
        return token

    def ssh_get_mic(self, session_id, gss_kex=False):
        """
        Create the MIC token for a SSH2 message.

        :param str session_id: The SSH session ID
        :param bool gss_kex: Generate the MIC for Key Exchange with SSPI or not
        :return: gssapi-with-mic:
                 Returns the MIC token from SSPI for the message we created
                 with ``_ssh_build_mic``.
                 gssapi-keyex:
                 Returns the MIC token from SSPI with the SSH session ID as
                 message.
        """
        self._session_id = session_id
        if not gss_kex:
            mic_field = self._ssh_build_mic(
                self._session_id,
                self._username,
                self._service,
                self._auth_method,
            )
            mic_token = self._gss_ctxt.sign(mic_field)
        else:
            # for key exchange with gssapi-keyex
            mic_token = self._gss_srv_ctxt.sign(self._session_id)
        return mic_token

    def ssh_accept_sec_context(self, hostname, username, recv_token):
        """
        Accept a SSPI context (server mode).

        :param str hostname: The servers FQDN
        :param str username: The name of the user who attempts to login
        :param str recv_token: The SSPI Token received from the server,
                               if it's not the initial call.
        :return: A ``String`` if the SSPI has returned a token or ``None`` if
                 no token was returned
        """
        self._gss_host = hostname
        self._username = username
        targ_name = "host/" + self._gss_host
        self._gss_srv_ctxt = sspi.ServerAuth("Kerberos", spn=targ_name)
        error, token = self._gss_srv_ctxt.authorize(recv_token)
        token = token[0].Buffer
        if error == 0:
            self._gss_srv_ctxt_status = True
            token = None
        return token

    def ssh_check_mic(self, mic_token, session_id, username=None):
        """
        Verify the MIC token for a SSH2 message.

        :param str mic_token: The MIC token received from the client
        :param str session_id: The SSH session ID
        :param str username: The name of the user who attempts to login
        :return: None if the MIC check was successful
        :raises: ``sspi.error`` -- if the MIC check failed
        """
        self._session_id = session_id
        self._username = username
        if username is not None:
            # server mode
            mic_field = self._ssh_build_mic(
                self._session_id,
                self._username,
                self._service,
                self._auth_method,
            )
            # Verifies data and its signature.  If verification fails, an
            # sspi.error will be raised.
            self._gss_srv_ctxt.verify(mic_field, mic_token)
        else:
            # for key exchange with gssapi-keyex
            # client mode
            # Verifies data and its signature.  If verification fails, an
            # sspi.error will be raised.
            self._gss_ctxt.verify(self._session_id, mic_token)

    @property
    def credentials_delegated(self):
        """
        Checks if credentials are delegated (server mode).

        :return: ``True`` if credentials are delegated, otherwise ``False``
        """
        return self._gss_flags & sspicon.ISC_REQ_DELEGATE and (
            self._gss_srv_ctxt_status or self._gss_flags
        )

    def save_client_creds(self, client_token):
        """
        Save the Client token in a file. This is used by the SSH server
        to store the client credentials if credentials are delegated
        (server mode).

        :param str client_token: The SSPI token received form the client
        :raises:
            ``NotImplementedError`` -- Credential delegation is currently not
            supported in server mode
        """
        raise NotImplementedError
