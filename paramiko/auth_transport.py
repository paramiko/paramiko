#!/usr/bin/python

from transport import BaseTransport
from transport import _MSG_SERVICE_REQUEST, _MSG_SERVICE_ACCEPT, _MSG_USERAUTH_REQUEST, _MSG_USERAUTH_FAILURE, \
     _MSG_USERAUTH_SUCCESS, _MSG_USERAUTH_BANNER
from message import Message
from ssh_exception import SSHException
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL

_DISCONNECT_SERVICE_NOT_AVAILABLE, _DISCONNECT_AUTH_CANCELLED_BY_USER, \
    _DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 7, 13, 14



class Transport (BaseTransport):
    """
    Subclass of L{BaseTransport} that handles authentication.  This separation
    keeps either class file from being too unwieldy.
    """
    
    AUTH_SUCCESSFUL, AUTH_PARTIALLY_SUCCESSFUL, AUTH_FAILED = range(3)

    def __init__(self, sock):
        BaseTransport.__init__(self, sock)
        self.authenticated = False
        self.auth_event = None
        # for server mode:
        self.auth_username = None
        self.auth_fail_count = 0
        self.auth_complete = 0

    def __repr__(self):
        if not self.active:
            return '<paramiko.Transport (unconnected)>'
        out = '<paramiko.Transport'
        if self.local_cipher != '':
            out += ' (cipher %s)' % self.local_cipher
        if self.authenticated:
            if len(self.channels) == 1:
                out += ' (active; 1 open channel)'
            else:
                out += ' (active; %d open channels)' % len(self.channels)
        elif self.initial_kex_done:
            out += ' (connected; awaiting auth)'
        else:
            out += ' (connecting)'
        out += '>'
        return out

    def is_authenticated(self):
        """
        Return true if this session is active and authenticated.

        @return: True if the session is still open and has been authenticated successfully;
        False if authentication failed and/or the session is closed.
        """
        return self.authenticated and self.active

    def auth_key(self, username, key, event):
        """
        Authenticate to the server using a private key.  The key is used to
        sign data from the server, so it must include the private part.  The
        given L{event} is triggered on success or failure.  On success,
        L{is_authenticated} will return C{True}.

        @param username: the username to authenticate as.
        @type username: string
        @param key: the private key to authenticate with.
        @type key: L{PKey <pkey.PKey>}
        @param event: an event to trigger when the authentication attempt is
        complete (whether it was successful or not)
        @type event: threading.Event
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException('No existing session')
        try:
            self.lock.acquire()
            self.auth_event = event
            self.auth_method = 'publickey'
            self.username = username
            self.private_key = key
            self._request_auth()
        finally:
            self.lock.release()

    def auth_password(self, username, password, event):
        """
        Authenticate to the server using a password.  The username and password
        are sent over an encrypted link, and the given L{event} is triggered on
        success or failure.  On success, L{is_authenticated} will return
        C{True}.

        @param username: the username to authenticate as.
        @type username: string
        @param password: the password to authenticate with.
        @type password: string
        @param event: an event to trigger when the authentication attempt is
        complete (whether it was successful or not)
        @type event: threading.Event
        """
        if (not self.active) or (not self.initial_kex_done):
            # we should never try to send the password unless we're on a secure link
            raise SSHException('No existing session')
        try:
            self.lock.acquire()
            self.auth_event = event
            self.auth_method = 'password'
            self.username = username
            self.password = password
            self._request_auth()
        finally:
            self.lock.release()

    def get_allowed_auths(self, username):
        "override me!"
        return 'password'

    def check_auth_none(self, username):
        "override me!  return int ==> auth status"
        return self.AUTH_FAILED

    def check_auth_password(self, username, password):
        "override me!  return int ==> auth status"
        return self.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """
        I{(subclass override)}
        Determine if a given key supplied by the client is acceptable for use
        in authentication.  You should override this method in server mode to
        check the username and key and decide if you would accept a signature
        made using this key.

        Return C{AUTH_FAILED} if the key is not accepted, C{AUTH_SUCCESSFUL}
        if the key is accepted and completes the authentication, or
        C{AUTH_PARTIALLY_SUCCESSFUL} if your authentication is stateful, and
        this key is accepted for authentication, but more authentication is
        required.  (In this latter case, L{get_allowed_auths} will be called
        to report to the client what options it has for continuing the
        authentication.)

        The default implementation always returns C{AUTH_FAILED}.

        @param username: the username of the authenticating client.
        @type username: string
        @param key: the key object provided by the client.
        @type key: L{PKey <pkey.PKey>}
        @return: C{AUTH_FAILED} if the client can't authenticate with this key;
        C{AUTH_SUCCESSFUL} if it can; C{AUTH_PARTIALLY_SUCCESSFUL} if it can
        authenticate with this key but must continue with authentication.
        @rtype: int
        """
        return self.AUTH_FAILED


    ###  internals...


    def _request_auth(self):
        m = Message()
        m.add_byte(chr(_MSG_SERVICE_REQUEST))
        m.add_string('ssh-userauth')
        self._send_message(m)

    def _disconnect_service_not_available(self):
        m = Message()
        m.add_byte(chr(_MSG_DISCONNECT))
        m.add_int(_DISCONNECT_SERVICE_NOT_AVAILABLE)
        m.add_string('Service not available')
        m.add_string('en')
        self._send_message(m)
        self.close()

    def _disconnect_no_more_auth(self):
        m = Message()
        m.add_byte(chr(_MSG_DISCONNECT))
        m.add_int(_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
        m.add_string('No more auth methods available')
        m.add_string('en')
        self._send_message(m)
        self.close()

    def _get_session_blob(self, key, service, username):
        m = Message()
        m.add_string(self.session_id)
        m.add_byte(chr(_MSG_USERAUTH_REQUEST))
        m.add_string(username)
        m.add_string(service)
        m.add_string('publickey')
        m.add_boolean(1)
        m.add_string(key.get_name())
        m.add_string(str(key))
        return str(m)

    def _parse_service_request(self, m):
        service = m.get_string()
        if self.server_mode and (service == 'ssh-userauth'):
            # accepted
            m = Message()
            m.add_byte(chr(_MSG_SERVICE_ACCEPT))
            m.add_string(service)
            self._send_message(m)
            return
        # dunno this one
        self._disconnect_service_not_available()

    def _parse_service_accept(self, m):
        service = m.get_string()
        if service == 'ssh-userauth':
            self._log(DEBUG, 'userauth is OK')
            m = Message()
            m.add_byte(chr(_MSG_USERAUTH_REQUEST))
            m.add_string(self.username)
            m.add_string('ssh-connection')
            m.add_string(self.auth_method)
            if self.auth_method == 'password':
                m.add_boolean(0)
                m.add_string(self.password.encode('UTF-8'))
            elif self.auth_method == 'publickey':
                m.add_boolean(1)
                m.add_string(self.private_key.get_name())
                m.add_string(str(self.private_key))
                blob = self._get_session_blob(self.private_key, 'ssh-connection', self.username)
                sig = self.private_key.sign_ssh_data(self.randpool, blob)
                m.add_string(str(sig))
            else:
                raise SSHException('Unknown auth method "%s"' % self.auth_method)
            self._send_message(m)
        else:
            self._log(DEBUG, 'Service request "%s" accepted (?)' % service)

    def _parse_userauth_request(self, m):
        if not self.server_mode:
            # er, uh... what?
            m = Message()
            m.add_byte(chr(_MSG_USERAUTH_FAILURE))
            m.add_string('none')
            m.add_boolean(0)
            self._send_message(m)
            return
        if self.auth_complete:
            # ignore
            return
        username = m.get_string()
        service = m.get_string()
        method = m.get_string()
        self._log(DEBUG, 'Auth request (type=%s) service=%s, username=%s' % (method, service, username))
        if service != 'ssh-connection':
            self._disconnect_service_not_available()
            return
        if (self.auth_username is not None) and (self.auth_username != username):
            self._log(DEBUG, 'Auth rejected because the client attempted to change username in mid-flight')
            self._disconnect_no_more_auth()
            return
        if method == 'none':
            result = self.check_auth_none(username)
        elif method == 'password':
            changereq = m.get_boolean()
            password = m.get_string().decode('UTF-8')
            if changereq:
                # always treated as failure, since we don't support changing passwords, but collect
                # the list of valid auth types from the callback anyway
                self._log(DEBUG, 'Auth request to change passwords (rejected)')
                newpassword = m.get_string().decode('UTF-8')
                result = self.AUTH_FAILED
            else:
                result = self.check_auth_password(username, password)
        elif method == 'publickey':
            sig_attached = m.get_boolean()
            keytype = m.get_string()
            keyblob = m.get_string()
            key = self._key_from_blob(keytype, keyblob)
            if (key is None) or (not key.valid):
                self._log(DEBUG, 'Auth rejected: unsupported or mangled public key')
                self._disconnect_no_more_auth()
                return
            # first check if this key is okay... if not, we can skip the verify
            result = self.check_auth_publickey(username, key)
            if result != self.AUTH_FAILED:
                # key is okay, verify it
                if not sig_attached:
                    # client wants to know if this key is acceptable, before it
                    # signs anything...  send special "ok" message
                    m = Message()
                    m.add_byte(chr(_MSG_USERAUTH_PK_OK))
                    m.add_string(keytype)
                    m.add_string(keyblob)
                    self._send_message(m)
                    return
                sig = Message(m.get_string())
                blob = self._get_session_blob(key, service, username)
                if not key.verify_ssh_sig(blob, sig):
                    self._log(DEBUG, 'Auth rejected: invalid signature')
                    result = self.AUTH_FAILED
        else:
            result = self.check_auth_none(username)
        # okay, send result
        m = Message()
        if result == self.AUTH_SUCCESSFUL:
            self._log(DEBUG, 'Auth granted.')
            m.add_byte(chr(_MSG_USERAUTH_SUCCESS))
            self.auth_complete = 1
        else:
            self._log(DEBUG, 'Auth rejected.')
            m.add_byte(chr(_MSG_USERAUTH_FAILURE))
            m.add_string(self.get_allowed_auths(username))
            if result == self.AUTH_PARTIALLY_SUCCESSFUL:
                m.add_boolean(1)
            else:
                m.add_boolean(0)
            self.auth_fail_count += 1
        self._send_message(m)
        if self.auth_fail_count >= 10:
            self._disconnect_no_more_auth()

    def _parse_userauth_success(self, m):
        self._log(INFO, 'Authentication successful!')
        self.authenticated = True
        if self.auth_event != None:
            self.auth_event.set()

    def _parse_userauth_failure(self, m):
        authlist = m.get_list()
        partial = m.get_boolean()
        if partial:
            self._log(INFO, 'Authentication continues...')
            self._log(DEBUG, 'Methods: ' + str(partial))
            # FIXME - do something
            pass
        self._log(INFO, 'Authentication failed.')
        self.authenticated = False
        self.close()
        if self.auth_event != None:
            self.auth_event.set()

    def _parse_userauth_banner(self, m):
        banner = m.get_string()
        lang = m.get_string()
        self._log(INFO, 'Auth banner: ' + banner)
        # who cares.

    _handler_table = BaseTransport._handler_table.copy()
    _handler_table.update({
        _MSG_SERVICE_REQUEST: _parse_service_request,
        _MSG_SERVICE_ACCEPT: _parse_service_accept,
        _MSG_USERAUTH_REQUEST: _parse_userauth_request,
        _MSG_USERAUTH_SUCCESS: _parse_userauth_success,
        _MSG_USERAUTH_FAILURE: _parse_userauth_failure,
        _MSG_USERAUTH_BANNER: _parse_userauth_banner,
        })

