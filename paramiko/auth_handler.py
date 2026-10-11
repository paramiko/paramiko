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
`.AuthHandler`
"""

import threading
import time
import weakref

from paramiko.common import (
    AUTH_FAILED,
    AUTH_PARTIALLY_SUCCESSFUL,
    AUTH_SUCCESSFUL,
    DEBUG,
    DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
    DISCONNECT_SERVICE_NOT_AVAILABLE,
    INFO,
    MSG_SERVICE_ACCEPT,
    MSG_SERVICE_REQUEST,
    MSG_USERAUTH_BANNER,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_INFO_REQUEST,
    MSG_USERAUTH_INFO_RESPONSE,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    WARNING,
    cMSG_DISCONNECT,
    cMSG_SERVICE_ACCEPT,
    cMSG_SERVICE_REQUEST,
    cMSG_USERAUTH_BANNER,
    cMSG_USERAUTH_FAILURE,
    cMSG_USERAUTH_INFO_REQUEST,
    cMSG_USERAUTH_INFO_RESPONSE,
    cMSG_USERAUTH_PK_OK,
    cMSG_USERAUTH_REQUEST,
    cMSG_USERAUTH_SUCCESS,
)
from paramiko.message import Message
from paramiko.server import InteractiveQuery
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    PartialAuthentication,
    SSHException,
)
from paramiko.util import b, u


class AuthHandler:
    """
    Internal class to handle the mechanics of authentication.
    """

    def __init__(self, transport):
        self.transport = weakref.proxy(transport)
        self.username = None
        self.authenticated = False
        self.auth_event = None
        self.auth_method = ""
        self.banner = None
        self.password = None
        self.private_key = None
        self.interactive_handler = None
        self.submethods = None
        # for server mode:
        self.auth_username = None
        self.auth_fail_count = 0

    def _log(self, *args):
        return self.transport._log(*args)

    def is_authenticated(self):
        return self.authenticated

    def get_username(self):
        if self.transport.server_mode:
            return self.auth_username
        else:
            return self.username

    def auth_none(self, username, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "none"
            self.username = username
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_publickey(self, username, key, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "publickey"
            self.username = username
            self.private_key = key
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_password(self, username, password, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "password"
            self.username = username
            self.password = password
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_interactive(self, username, handler, event, submethods=""):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "keyboard-interactive"
            self.username = username
            self.interactive_handler = handler
            self.submethods = submethods
            self._request_auth()
        finally:
            self.transport.lock.release()

    def abort(self):
        if self.auth_event is not None:
            self.auth_event.set()

    # ...internals...

    def _request_auth(self):
        m = Message()
        m.add_byte(cMSG_SERVICE_REQUEST)
        m.add_string("ssh-userauth")
        self.transport._send_message(m)

    def _disconnect_service_not_available(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_SERVICE_NOT_AVAILABLE)
        m.add_string("Service not available")
        m.add_string("en")
        self.transport._send_message(m)
        self.transport.close()

    def _disconnect_no_more_auth(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
        m.add_string("No more auth methods available")
        m.add_string("en")
        self.transport._send_message(m)
        self.transport.close()

    def _get_key_type_and_bits(self, key):
        """
        Given any key, return its type/algorithm & bits-to-sign.

        Intended for input to or verification of, key signatures.
        """
        # Use certificate contents, if available, plain pubkey otherwise
        if key.public_blob:
            return key.public_blob.key_type, key.public_blob.key_blob
        else:
            return key.get_name(), key

    def _get_session_blob(self, key, service, username, algorithm):
        m = Message()
        m.add_string(self.transport.session_id)
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string(service)
        m.add_string("publickey")
        m.add_boolean(True)
        _, bits = self._get_key_type_and_bits(key)
        m.add_string(algorithm)
        m.add_string(bits)
        return m.asbytes()

    def wait_for_response(self, event):
        max_ts = None
        if self.transport.auth_timeout is not None:
            max_ts = time.time() + self.transport.auth_timeout
        while True:
            event.wait(0.1)
            if not self.transport.is_active():
                e = self.transport.get_exception()
                if (e is None) or issubclass(e.__class__, EOFError):
                    e = AuthenticationException(
                        "Authentication failed: transport shut down or saw EOF"
                    )
                raise e
            if event.is_set():
                break
            if max_ts is not None and max_ts <= time.time():
                raise AuthenticationException("Authentication timeout.")

        if not self.is_authenticated():
            e = self.transport.get_exception()
            if e is None:
                e = AuthenticationException("Authentication failed.")
            # this is horrible.  Python Exception isn't yet descended from
            # object, so type(e) won't work. :(
            # TODO (backwards incompat): lol. just lmao.
            if issubclass(e.__class__, PartialAuthentication):
                return e.allowed_types
            raise e
        return []

    def _parse_service_request(self, m):
        service = m.get_text()
        if self.transport.server_mode and (service == "ssh-userauth"):
            # accepted
            m = Message()
            m.add_byte(cMSG_SERVICE_ACCEPT)
            m.add_string(service)
            self.transport._send_message(m)
            banner, language = self.transport.server_object.get_banner()
            if banner:
                m = Message()
                m.add_byte(cMSG_USERAUTH_BANNER)
                m.add_string(banner)
                m.add_string(language)
                self.transport._send_message(m)
            return
        # dunno this one
        self._disconnect_service_not_available()

    def _generate_key_from_request(self, algorithm, keyblob):
        # For use in server mode.
        options = self.transport.preferred_pubkeys
        if algorithm.replace("-cert-v01@openssh.com", "") not in options:
            err = (
                "Auth rejected: pubkey algorithm '{}' unsupported or disabled"
            )
            self._log(INFO, err.format(algorithm))
            return None
        return self.transport._key_info[algorithm](Message(keyblob))

    def _finalize_pubkey_algorithm(self, key_type):
        """
        Given a key type, decide which pubkey algorithm to use with it.

        In most cases this is simply "that key type, again".

        For RSA, this will be one of the SHA2 algorithms, depending on our
        (transport's) configured pubkey algorithms list.
        """
        # Short-circuit for non-RSA keys
        if "rsa" not in key_type:
            return key_type
        self._log(
            DEBUG,
            "Finalizing pubkey algorithm for key of type {!r}".format(
                key_type
            ),
        )
        # Normal attempts to handshake follow from here.
        # Only consider RSA algos from our list, lest we agree on another!
        my_algos = [x for x in self.transport.preferred_pubkeys if "rsa" in x]
        self._log(DEBUG, "Our pubkey algorithm list: {}".format(my_algos))
        # Short-circuit negatively if user disabled all RSA algos (heh)
        if not my_algos:
            raise SSHException(
                "An RSA key was specified, but no RSA pubkey algorithms are configured!"  # noqa
            )
        # Check for server-sig-algs if supported & sent
        server_algo_str = u(
            self.transport.server_extensions.get("server-sig-algs", b(""))
        )
        pubkey_algo = None
        # Prefer to match against server-sig-algs
        if server_algo_str:
            server_algos = server_algo_str.split(",")
            self._log(
                DEBUG, "Server-side algorithm list: {}".format(server_algos)
            )
            # Only use algos from our list that the server likes, in our own
            # preference order. (NOTE: purposefully using same style as in
            # Transport...expect to refactor later)
            agreement = list(filter(server_algos.__contains__, my_algos))
            if agreement:
                pubkey_algo = agreement[0]
                self._log(
                    DEBUG,
                    "Agreed upon {!r} pubkey algorithm".format(pubkey_algo),
                )
            else:
                self._log(DEBUG, "No common pubkey algorithms exist! Dying.")
                # TODO: MAY want to use IncompatiblePeer again here but that's
                # technically for initial key exchange, not pubkey auth.
                err = "Unable to agree on a pubkey algorithm for signing a {!r} key!"  # noqa
                raise AuthenticationException(err.format(key_type))
        # Fallback to first item in our preferred algorithm list (which won't
        # be empty due to guardrail above)
        else:
            pubkey_algo = my_algos[0]
            msg = f"Server did not send a server-sig-algs list; defaulting to first RSA algorithm in our list: {pubkey_algo}"  # noqa
            self._log(DEBUG, msg)
        # If we had loaded a cert-type key, tack that on to the algorithm name
        # to get the final correct result.
        if key_type.endswith("-cert-v01@openssh.com"):
            pubkey_algo += "-cert-v01@openssh.com"
        self.transport._agreed_pubkey_algorithm = pubkey_algo
        return pubkey_algo

    def _parse_service_accept(self, m):
        service = m.get_text()
        if service == "ssh-userauth":
            self._log(DEBUG, "userauth is OK")
            m = Message()
            m.add_byte(cMSG_USERAUTH_REQUEST)
            m.add_string(self.username)
            m.add_string("ssh-connection")
            m.add_string(self.auth_method)
            if self.auth_method == "password":
                m.add_boolean(False)
                password = b(self.password)
                m.add_string(password)
            elif self.auth_method == "publickey":
                m.add_boolean(True)
                key_type, bits = self._get_key_type_and_bits(self.private_key)
                algorithm = self._finalize_pubkey_algorithm(key_type)
                m.add_string(algorithm)
                m.add_string(bits)
                blob = self._get_session_blob(
                    self.private_key,
                    "ssh-connection",
                    self.username,
                    algorithm,
                )
                sig = self.private_key.sign_ssh_data(blob, algorithm)
                m.add_string(sig)
            elif self.auth_method == "keyboard-interactive":
                m.add_string("")
                m.add_string(self.submethods)
            elif self.auth_method == "none":
                pass
            else:
                raise SSHException(
                    'Unknown auth method "{}"'.format(self.auth_method)
                )
            self.transport._send_message(m)
        else:
            self._log(
                DEBUG, 'Service request "{}" accepted (?)'.format(service)
            )

    def _send_auth_result(self, username, method, result):
        # okay, send result
        m = Message()
        if result == AUTH_SUCCESSFUL:
            self._log(INFO, "Auth granted ({}).".format(method))
            m.add_byte(cMSG_USERAUTH_SUCCESS)
            self.authenticated = True
        else:
            self._log(INFO, "Auth rejected ({}).".format(method))
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string(
                self.transport.server_object.get_allowed_auths(username)
            )
            if result == AUTH_PARTIALLY_SUCCESSFUL:
                m.add_boolean(True)
            else:
                m.add_boolean(False)
                self.auth_fail_count += 1
        self.transport._send_message(m)
        if self.auth_fail_count >= 10:
            self._disconnect_no_more_auth()
        if result == AUTH_SUCCESSFUL:
            self.transport._auth_trigger()

    def _interactive_query(self, q):
        # make interactive query instead of response
        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_REQUEST)
        m.add_string(q.name)
        m.add_string(q.instructions)
        m.add_string(bytes())
        m.add_int(len(q.prompts))
        for p in q.prompts:
            m.add_string(p[0])
            m.add_boolean(p[1])
        self.transport._send_message(m)

    def _parse_userauth_request(self, m):
        if not self.transport.server_mode:
            # er, uh... what?
            m = Message()
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string("none")
            m.add_boolean(False)
            self.transport._send_message(m)
            return
        if self.authenticated:
            # ignore
            return
        username = m.get_text()
        service = m.get_text()
        method = m.get_text()
        self._log(
            DEBUG,
            "Auth request (type={}) service={}, username={}".format(
                method, service, username
            ),
        )
        if service != "ssh-connection":
            self._disconnect_service_not_available()
            return
        if (self.auth_username is not None) and (
            self.auth_username != username
        ):
            self._log(
                WARNING,
                "Auth rejected because the client attempted to change username in mid-flight",  # noqa
            )
            self._disconnect_no_more_auth()
            return
        self.auth_username = username

        if method == "none":
            result = self.transport.server_object.check_auth_none(username)
        elif method == "password":
            changereq = m.get_boolean()
            password = m.get_binary()
            try:
                password = password.decode("UTF-8")
            except UnicodeError:
                # some clients/servers expect non-utf-8 passwords!
                # in this case, just return the raw byte string.
                pass
            if changereq:
                # always treated as failure, since we don't support changing
                # passwords, but collect the list of valid auth types from
                # the callback anyway
                self._log(DEBUG, "Auth request to change passwords (rejected)")
                newpassword = m.get_binary()
                try:
                    newpassword = newpassword.decode("UTF-8", "replace")
                except UnicodeError:
                    pass
                result = AUTH_FAILED
            else:
                result = self.transport.server_object.check_auth_password(
                    username, password
                )
        elif method == "publickey":
            sig_attached = m.get_boolean()
            # NOTE: server never wants to guess a client's algo, they're
            # telling us directly. No need for _finalize_pubkey_algorithm
            # anywhere in this flow.
            # TODO: ok is this a spot where it can say a SHA2 dealie in some
            # fields but still ssh-rsa within the pubkey blob part?
            # TODO: ok so this would be rsa-sha2-256 or w/e, if this field says
            # ssh-rsa the request can get stuffed.
            algorithm = m.get_text()
            # TODO: This part would, if deconstructed, still be allowed to have
            # "ssh-rsa" in its first field.
            keyblob = m.get_binary()
            try:
                key = self._generate_key_from_request(algorithm, keyblob)
            except SSHException as e:
                self._log(INFO, "Auth rejected: public key: {}".format(str(e)))
                key = None
            except Exception as e:
                msg = "Auth rejected: unsupported or mangled public key ({}: {})"  # noqa
                self._log(INFO, msg.format(e.__class__.__name__, e))
                key = None
            if key is None:
                self._disconnect_no_more_auth()
                return
            # first check if this key is okay... if not, we can skip the verify
            result = self.transport.server_object.check_auth_publickey(
                username, key
            )
            if result != AUTH_FAILED:
                # key is okay, verify it
                if not sig_attached:
                    # client wants to know if this key is acceptable, before it
                    # signs anything...  send special "ok" message
                    m = Message()
                    m.add_byte(cMSG_USERAUTH_PK_OK)
                    m.add_string(algorithm)
                    m.add_string(keyblob)
                    self.transport._send_message(m)
                    return
                sig = Message(m.get_binary())
                blob = self._get_session_blob(
                    key, service, username, algorithm
                )
                if not key.verify_ssh_sig(blob, sig):
                    self._log(INFO, "Auth rejected: invalid signature")
                    result = AUTH_FAILED
        elif method == "keyboard-interactive":
            submethods = m.get_string()
            result = self.transport.server_object.check_auth_interactive(
                username, submethods
            )
            if isinstance(result, InteractiveQuery):
                # make interactive query instead of response
                self._interactive_query(result)
                return
        else:
            result = self.transport.server_object.check_auth_none(username)
        # okay, send result
        self._send_auth_result(username, method, result)

    def _parse_userauth_success(self, m):
        self._log(
            INFO, "Authentication ({}) successful!".format(self.auth_method)
        )
        self.authenticated = True
        self.transport._auth_trigger()
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_failure(self, m):
        authlist = m.get_list()
        # TODO (backwards incompat): we aren't giving callers access to
        # authlist _unless_ it's partial authentication, so eg authtype=none
        # can't work unless we tweak this.
        partial = m.get_boolean()
        if partial:
            self._log(INFO, "Authentication continues...")
            self._log(DEBUG, "Methods: " + str(authlist))
            self.transport.saved_exception = PartialAuthentication(authlist)
        elif self.auth_method not in authlist:
            for msg in (
                "Authentication type ({}) not permitted.".format(
                    self.auth_method
                ),
                "Allowed methods: {}".format(authlist),
            ):
                self._log(DEBUG, msg)
            self.transport.saved_exception = BadAuthenticationType(
                "Bad authentication type", authlist
            )
        else:
            self._log(
                INFO, "Authentication ({}) failed.".format(self.auth_method)
            )
        self.authenticated = False
        self.username = None
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_banner(self, m):
        banner = m.get_string()
        self.banner = banner
        self._log(INFO, "Auth banner: {}".format(banner))
        # who cares.

    def _parse_userauth_info_request(self, m):
        if self.auth_method != "keyboard-interactive":
            raise SSHException("Illegal info request from server")
        title = m.get_text()
        instructions = m.get_text()
        m.get_binary()  # lang
        prompts = m.get_int()
        prompt_list = []
        for i in range(prompts):
            prompt_list.append((m.get_text(), m.get_boolean()))
        response_list = self.interactive_handler(
            title, instructions, prompt_list
        )

        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_RESPONSE)
        m.add_int(len(response_list))
        for r in response_list:
            m.add_string(r)
        self.transport._send_message(m)

    def _parse_userauth_info_response(self, m):
        if not self.transport.server_mode:
            raise SSHException("Illegal info response from server")
        n = m.get_int()
        responses = []
        for i in range(n):
            responses.append(m.get_text())
        result = self.transport.server_object.check_auth_interactive_response(
            responses
        )
        if isinstance(result, InteractiveQuery):
            # make interactive query instead of response
            self._interactive_query(result)
            return
        self._send_auth_result(
            self.auth_username, "keyboard-interactive", result
        )

    # TODO (backwards incompat): MAY make sense to make these tables into
    # actual classes/instances that can be fed a mode bool or whatever. Or,
    # alternately (both?) make the message types small classes or enums that
    # embed this info within themselves (which could also then tidy up the
    # current 'integer -> human readable short string' stuff in common.py).
    # TODO: if we do that, also expose 'em publicly.

    # Messages which should be handled _by_ servers (sent by clients)
    @property
    def _server_handler_table(self):
        return {
            # TODO (backwards incompat): MSG_SERVICE_REQUEST ought to
            # eventually move into Transport's server mode like the client side
            # did, just for consistency.
            MSG_SERVICE_REQUEST: self._parse_service_request,
            MSG_USERAUTH_REQUEST: self._parse_userauth_request,
            MSG_USERAUTH_INFO_RESPONSE: self._parse_userauth_info_response,
        }

    # Messages which should be handled _by_ clients (sent by servers)
    @property
    def _client_handler_table(self):
        return {
            MSG_SERVICE_ACCEPT: self._parse_service_accept,
            MSG_USERAUTH_SUCCESS: self._parse_userauth_success,
            MSG_USERAUTH_FAILURE: self._parse_userauth_failure,
            MSG_USERAUTH_BANNER: self._parse_userauth_banner,
            MSG_USERAUTH_INFO_REQUEST: self._parse_userauth_info_request,
        }

    # NOTE: prior to the fix for #1283, this was a static dict instead of a
    # property. Should be backwards compatible in most/all cases.
    @property
    def _handler_table(self):
        if self.transport.server_mode:
            return self._server_handler_table
        else:
            return self._client_handler_table


class AuthOnlyHandler(AuthHandler):
    """
    AuthHandler, and just auth, no service requests!

    .. versionadded:: 3.2
    """

    # NOTE: this purposefully duplicates some of the parent class in order to
    # modernize, refactor, etc. The intent is that eventually we will collapse
    # this one onto the parent in a backwards incompatible release.

    @property
    def _client_handler_table(self):
        my_table = super()._client_handler_table.copy()
        del my_table[MSG_SERVICE_ACCEPT]
        return my_table

    def send_auth_request(self, username, method, finish_message=None):
        """
        Submit a userauth request message & wait for response.

        Performs the transport message send call, sets self.auth_event, and
        will lock-n-block as necessary to both send, and wait for response to,
        the USERAUTH_REQUEST.

        Most callers will want to supply a callback to ``finish_message``,
        which accepts a Message ``m`` and may call mutator methods on it to add
        more fields.
        """
        # Store a few things for reference in handlers, including auth failure
        # handler (which needs to know if we were using a bad method, etc)
        self.auth_method = method
        self.username = username
        # Generic userauth request fields
        m = Message()
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string("ssh-connection")
        m.add_string(method)
        # Caller usually has more to say, such as injecting password, key etc
        finish_message(m)
        # TODO (backwards incompat): seems odd to have the client handle the
        # lock and not Transport; that _may_ have been an artifact of allowing
        # user threading event injection? Regardless, we don't want to move
        # _this_ locking into Transport._send_message now, because lots of
        # other untouched code also uses that method and we might end up
        # double-locking (?) but 4.0 would be a good time to revisit.
        with self.transport.lock:
            self.transport._send_message(m)
        # We have cut out the higher level event args, but self.auth_event is
        # still required for self.wait_for_response to function correctly (it's
        # the mechanism used by the auth success/failure handlers, the abort
        # handler, and a few other spots.
        # TODO: interestingly, wait_for_response itself doesn't actually
        # enforce that its event argument and self.auth_event are the same...
        self.auth_event = threading.Event()
        return self.wait_for_response(self.auth_event)

    def auth_none(self, username):
        return self.send_auth_request(username, "none")

    def auth_publickey(self, username, key):
        # NOTE: key_type here may be just key type ("rsa-sha2-256") or may be
        # the cert form if cert was loaded ("ssh-rsa-cert-v01@openssh.com")
        key_type, bits = self._get_key_type_and_bits(key)
        algorithm = self._finalize_pubkey_algorithm(key_type)
        blob = self._get_session_blob(
            key,
            "ssh-connection",
            username,
            algorithm,
        )

        def finish(m):
            # This field doesn't appear to be named, but is False when querying
            # for permission (ie knowing whether to even prompt a user for
            # passphrase, etc) or True when just going for it. Paramiko has
            # never bothered with the former type of message, apparently.
            m.add_boolean(True)
            m.add_string(algorithm)
            m.add_string(bits)
            m.add_string(key.sign_ssh_data(blob, algorithm))

        return self.send_auth_request(username, "publickey", finish)

    def auth_password(self, username, password):
        def finish(m):
            # Unnamed field that equates to "I am changing my password", which
            # Paramiko clientside never supported and serverside only sort of
            # supported.
            m.add_boolean(False)
            m.add_string(b(password))

        return self.send_auth_request(username, "password", finish)

    def auth_interactive(self, username, handler, submethods=""):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        # Unlike most siblings, this auth method _does_ require other
        # superclass handlers (eg userauth info request) to understand
        # what's going on, so we still set some self attributes.
        self.auth_method = "keyboard_interactive"
        self.interactive_handler = handler

        def finish(m):
            # Empty string for deprecated language tag field, per RFC 4256:
            # https://www.rfc-editor.org/rfc/rfc4256#section-3.1
            m.add_string("")
            m.add_string(submethods)

        return self.send_auth_request(username, "keyboard-interactive", finish)
