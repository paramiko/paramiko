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
Abstraction for an SSH2 channel.
"""

import time, threading, socket, os

from common import *
import util
from message import Message
from ssh_exception import SSHException
from file import BufferedFile


# this is ugly, and won't work on windows
def _set_nonblocking(fd):
    import fcntl
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)


class Channel (object):
    """
    A secure tunnel across an SSH L{Transport}.  A Channel is meant to behave
    like a socket, and has an API that should be indistinguishable from the
    python socket API.

    Because SSH2 has a windowing kind of flow control, if you stop reading data
    from a Channel and its buffer fills up, the server will be unable to send
    you any more data until you read some of it.  (This won't affect other
    channels on the same transport -- all channels on a single transport are
    flow-controlled independently.)  Similarly, if the server isn't reading
    data you send, calls to L{send} may block, unless you set a timeout.  This
    is exactly like a normal network socket, so it shouldn't be too surprising.
    """

    def __init__(self, chanid):
        """
        Create a new channel.  The channel is not associated with any
        particular session or L{Transport} until the Transport attaches it.
        Normally you would only call this method from the constructor of a
        subclass of L{Channel}.

        @param chanid: the ID of this channel, as passed by an existing
        L{Transport}.
        @type chanid: int
        """
        self.chanid = chanid
        self.transport = None
        self.active = 0
        self.eof_received = 0
        self.eof_sent = 0
        self.in_buffer = ''
        self.timeout = None
        self.closed = False
        self.lock = threading.Lock()
        self.in_buffer_cv = threading.Condition(self.lock)
        self.out_buffer_cv = threading.Condition(self.lock)
        self.name = str(chanid)
        self.logger = logging.getLogger('paramiko.chan.' + str(chanid))
        self.pipe_rfd = self.pipe_wfd = None

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.

        @rtype: string
        """
        out = '<paramiko.Channel %d' % self.chanid
        if self.closed:
            out += ' (closed)'
        elif self.active:
            if self.eof_received:
                out += ' (EOF received)'
            if self.eof_sent:
                out += ' (EOF sent)'
            out += ' (open) window=%d' % (self.out_window_size)
            if len(self.in_buffer) > 0:
                out += ' in-buffer=%d' % (len(self.in_buffer),)
        out += ' -> ' + repr(self.transport)
        out += '>'
        return out

    def get_pty(self, term='vt100', width=80, height=24):
        """
        Request a pseudo-terminal from the server.  This is usually used right
        after creating a client channel, to ask the server to provide some
        basic terminal semantics for the next command you execute.

        @param term: the terminal type to emulate (for example, C{'vt100'}).
        @type term: string
        @param width: width (in characters) of the terminal screen
        @type width: int
        @param height: height (in characters) of the terminal screen
        @type height: int
        """
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('pty-req')
        m.add_boolean(0)
        m.add_string(term)
        m.add_int(width)
        m.add_int(height)
        # pixel height, width (usually useless)
        m.add_int(0).add_int(0)
        m.add_string('')
        self.transport._send_message(m)

    def invoke_shell(self):
        """
        Request an interactive shell session on this channel.  If the server
        allows it, the channel will then be directly connected to the stdin
        and stdout of the shell.
        """
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('shell')
        m.add_boolean(1)
        self.transport._send_message(m)

    def exec_command(self, command):
        """
        Execute a command on the server.  If the server allows it, the channel
        will then be directly connected to the stdin and stdout of the command
        being executed.

        @param command: a shell command to execute.
        @type command: string
        """
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('exec')
        m.add_boolean(1)
        m.add_string(command)
        self.transport._send_message(m)

    def invoke_subsystem(self, subsystem):
        """
        Request a subsystem on the server (for example, C{sftp}).  If the
        server allows it, the channel will then be directly connected to the
        requested subsystem.

        @param subsystem: name of the subsystem being requested.
        @type subsystem: string
        """
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('subsystem')
        m.add_boolean(1)
        m.add_string(subsystem)
        self.transport._send_message(m)

    def resize_pty(self, width=80, height=24):
        """
        Resize the pseudo-terminal.  This can be used to change the width and
        height of the terminal emulation created in a previous L{get_pty} call.

        @param width: new width (in characters) of the terminal screen
        @type width: int
        @param height: new height (in characters) of the terminal screen
        @type height: int
        """
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('window-change')
        m.add_boolean(0)
        m.add_int(width)
        m.add_int(height)
        m.add_int(0).add_int(0)
        self.transport._send_message(m)

    def get_transport(self):
        """
        Return the L{Transport} associated with this channel.

        @return: the L{Transport} that was used to create this channel.
        @rtype: L{Transport}
        """
        return self.transport

    def set_name(self, name):
        """
        Set a name for this channel.  Currently it's only used to set the name
        of the log level used for debugging.  The name can be fetched with the
        L{get_name} method.

        @param name: new channel name
        @type name: string
        """
        self.name = name
        self.logger = logging.getLogger('paramiko.chan.' + name)

    def get_name(self):
        """
        Get the name of this channel that was previously set by L{set_name}.

        @return: the name of this channel
        @rtype: string
        """
        return self.name

    
    ###  socket API


    def settimeout(self, timeout):
        """
        Set a timeout on blocking read/write operations.  The C{timeout}
        argument can be a nonnegative float expressing seconds, or C{None}.  If
        a float is given, subsequent channel read/write operations will raise
        a timeout exception if the timeout period value has elapsed before the
        operation has completed.  Setting a timeout of C{None} disables
        timeouts on socket operations.

        C{chan.settimeout(0.0)} is equivalent to C{chan.setblocking(0)};
        C{chan.settimeout(None)} is equivalent to C{chan.setblocking(1)}.

        @param timeout: seconds to wait for a pending read/write operation
        before raising C{socket.timeout}, or C{None} for no timeout.
        @type timeout: float
        """
        self.timeout = timeout

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a float) associated with socket
        operations, or C{None} if no timeout is set.  This reflects the last
        call to L{setblocking} or L{settimeout}.

        @return: timeout in seconds, or C{None}.
        @rtype: float
        """
        return self.timeout

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode of the channel: if C{blocking} is 0,
        the channel is set to non-blocking mode; otherwise it's set to blocking
        mode.  Initially all channels are in blocking mode.

        In non-blocking mode, if a L{recv} call doesn't find any data, or if a
        L{send} call can't immediately dispose of the data, an error exception
        is raised.  In blocking mode, the calls block until they can proceed.

        C{chan.setblocking(0)} is equivalent to C{chan.settimeout(0)};
        C{chan.setblocking(1)} is equivalent to C{chan.settimeout(None)}.

        @param blocking: 0 to set non-blocking mode; non-0 to set blocking
        mode.
        @type blocking: int
        """
        if blocking:
            self.settimeout(None)
        else:
            self.settimeout(0.0)

    def close(self):
        """
        Close the channel.  All future read/write operations on the channel
        will fail.  The remote end will receive no more data (after queued data
        is flushed).  Channels are automatically closed when they are garbage-
        collected, or when their L{Transport} is closed.
        """
        try:
            self.lock.acquire()
            if self.active and not self.closed:
                self._send_eof()
                m = Message()
                m.add_byte(chr(MSG_CHANNEL_CLOSE))
                m.add_int(self.remote_chanid)
                self.transport._send_message(m)
                self._set_closed()
                self.transport._unlink_channel(self.chanid)
        finally:
            self.lock.release()

    def recv_ready(self):
        """
        Returns true if data is ready to be read from this channel.
        
        @return: C{True} if a L{recv} call on this channel would immediately
        return at least one byte; C{False} otherwise.
        @rtype: boolean
        
        @note: This method doesn't work if you've called L{fileno}.
        """
        try:
            self.lock.acquire()
            if len(self.in_buffer) == 0:
                return False
            return True
        finally:
            self.lock.release()

    def recv(self, nbytes):
        """
        Receive data from the channel.  The return value is a string
        representing the data received.  The maximum amount of data to be
        received at once is specified by C{nbytes}.  If a string of length zero
        is returned, the channel stream has closed.

        @param nbytes: maximum number of bytes to read.
        @type nbytes: int
        @return: data.
        @rtype: string
        
        @raise socket.timeout: if no data is ready before the timeout set by
        L{settimeout}.
        """
        out = ''
        try:
            self.lock.acquire()
            if self.pipe_rfd != None:
                # use the pipe
                return self._read_pipe(nbytes)
            if len(self.in_buffer) == 0:
                if self.closed or self.eof_received:
                    return out
                # should we block?
                if self.timeout == 0.0:
                    raise socket.timeout()
                # loop here in case we get woken up but a different thread has grabbed everything in the buffer
                timeout = self.timeout
                while (len(self.in_buffer) == 0) and not self.closed and not self.eof_received:
                    then = time.time()
                    self.in_buffer_cv.wait(timeout)
                    if timeout != None:
                        timeout -= time.time() - then
                        if timeout <= 0.0:
                            raise socket.timeout()
            # something in the buffer and we have the lock
            if len(self.in_buffer) <= nbytes:
                out = self.in_buffer
                self.in_buffer = ''
            else:
                out = self.in_buffer[:nbytes]
                self.in_buffer = self.in_buffer[nbytes:]
            self._check_add_window(len(out))
        finally:
            self.lock.release()
        return out

    def send(self, s):
        """
        Send data to the channel.  Returns the number of bytes sent, or 0 if
        the channel stream is closed.  Applications are responsible for
        checking that all data has been sent: if only some of the data was
        transmitted, the application needs to attempt delivery of the remaining
        data.

        @param s: data to send.
        @type s: string
        @return: number of bytes actually sent.
        @rtype: int

        @raise socket.timeout: if no data could be sent before the timeout set
        by L{settimeout}.
        """
        size = 0
        if self.closed or self.eof_sent:
            return size
        try:
            self.lock.acquire()
            if self.out_window_size == 0:
                # should we block?
                if self.timeout == 0.0:
                    raise socket.timeout()
                # loop here in case we get woken up but a different thread has filled the buffer
                timeout = self.timeout
                while self.out_window_size == 0:
                    then = time.time()
                    self.out_buffer_cv.wait(timeout)
                    if timeout != None:
                        timeout -= time.time() - then
                        if timeout <= 0.0:
                            raise socket.timeout()
            # we have some window to squeeze into
            if self.closed:
                return 0
            size = len(s)
            if self.out_window_size < size:
                size = self.out_window_size
            if self.out_max_packet_size < size:
                size = self.out_max_packet_size
            m = Message()
            m.add_byte(chr(MSG_CHANNEL_DATA))
            m.add_int(self.remote_chanid)
            m.add_string(s[:size])
            self.transport._send_message(m)
            self.out_window_size -= size
        finally:
            self.lock.release()
        return size

    def sendall(self, s):
        """
        Send data to the channel, without allowing partial results.  Unlike
        L{send}, this method continues to send data from the given string until
        either all data has been sent or an error occurs.  Nothing is returned.

        @param s: data to send.
        @type s: string

        @raise socket.timeout: if sending stalled for longer than the timeout
        set by L{settimeout}.
        @raise socket.error: if an error occured before the entire string was
        sent.
        
        @note: If the channel is closed while only part of the data hase been
        sent, there is no way to determine how much data (if any) was sent.
        This is irritating, but identically follows python's API.
        """
        while s:
            if self.closed:
                # this doesn't seem useful, but it is the documented behavior of Socket
                raise socket.error('Socket is closed')
            sent = self.send(s)
            s = s[sent:]
        return None

    def makefile(self, *params):
        """
        Return a file-like object associated with this channel, without the
        non-portable side effects of L{fileno}.  The optional C{mode} and
        C{bufsize} arguments are interpreted the same way as by the built-in
        C{file()} function in python.

        @return: object which can be used for python file I/O.
        @rtype: L{ChannelFile}
        """
        return ChannelFile(*([self] + list(params)))

    def fileno(self):
        """
        Returns an OS-level file descriptor which can be used for polling and
        reading (but I{not} for writing).  This is primaily to allow python's
        C{select} module to work.

        The first time C{fileno} is called on a channel, a pipe is created to
        simulate real OS-level file descriptor (FD) behavior.  Because of this,
        two actual FDs are created -- this may be inefficient if you plan to
        use many channels.

        @return: a small integer file descriptor
        @rtype: int
        
        @warning: This method causes several aspects of the channel to change
        behavior.  It is always more efficient to avoid using this method.

        @bug: This does not work on Windows.  The problem is that pipes are
        used to simulate an open FD, but I haven't figured out how to make
        pipes enter non-blocking mode on Windows yet.
        """
        try:
            self.lock.acquire()
            if self.pipe_rfd != None:
                return self.pipe_rfd
            # create the pipe and feed in any existing data
            self.pipe_rfd, self.pipe_wfd = os.pipe()
            _set_nonblocking(self.pipe_wfd)
            _set_nonblocking(self.pipe_rfd)
            if len(self.in_buffer) > 0:
                x = self.in_buffer
                self.in_buffer = ''
                self._feed_pipe(x)
            return self.pipe_rfd
        finally:
            self.lock.release()

    def shutdown(self, how):
        """
        Shut down one or both halves of the connection.  If C{how} is 0,
        further receives are disallowed.  If C{how} is 1, further sends
        are disallowed.  If C{how} is 2, further sends and receives are
        disallowed.  This closes the stream in one or both directions.

        @param how: 0 (stop receiving), 1 (stop sending), or 2 (stop
        receiving and sending).
        @type how: int
        """
        if (how == 0) or (how == 2):
            # feign "read" shutdown
            self.eof_received = 1
        if (how == 1) or (how == 2):
            self._send_eof()


    ###  overrides


    def check_pty_request(self, term, width, height, pixelwidth, pixelheight, modes):
        """
        I{(subclass override)}
        Determine if a pseudo-terminal of the given dimensions (usually
        requested for shell access) can be provided.

        The default implementation always returns C{False}.
        
        @param term: type of terminal requested (for example, C{"vt100"}).
        @type term: string
        @param width: width of screen in characters.
        @type width: int
        @param height: height of screen in characters.
        @type height: int
        @param pixelwidth: width of screen in pixels, if known (may be C{0} if
        unknown).
        @type pixelwidth: int
        @param pixelheight: height of screen in pixels, if known (may be C{0}
        if unknown).
        @type pixelheight: int
        @return: C{True} if the psuedo-terminal has been allocated; C{False}
        otherwise.
        @rtype: boolean
        """
        return False

    def check_shell_request(self):
        """
        I{(subclass override)}
        Determine if a shell will be provided to the client.  If this method
        returns C{True}, this channel should be connected to the stdin/stdout
        of a shell.

        The default implementation always returns C{False}.

        @return: C{True} if this channel is now hooked up to a shell; C{False}
        if a shell can't or won't be provided.
        @rtype: boolean
        """
        return False

    def check_subsystem_request(self, name):
        """
        I{(subclass override)}
        Determine if a requested subsystem will be provided to the client.  If
        this method returns C{True}, all future I/O through this channel will
        be assumed to be connected to the requested subsystem.  An example of
        a subsystem is C{sftp}.

        The default implementation always returns C{False}.

        @return: C{True} if this channel is now hooked up to the requested
        subsystem; C{False} if that subsystem can't or won't be provided.
        @rtype: boolean
        """
        return False

    def check_window_change_request(self, width, height, pixelwidth, pixelheight):
        """
        I{(subclass override)}
        Determine if the pseudo-terminal can be resized.

        The default implementation always returns C{False}.

        @param width: width of screen in characters.
        @type width: int
        @param height: height of screen in characters.
        @type height: int
        @param pixelwidth: width of screen in pixels, if known (may be C{0} if
        unknown).
        @type pixelwidth: int
        @param pixelheight: height of screen in pixels, if known (may be C{0}
        if unknown).
        @type pixelheight: int
        @return: C{True} if the terminal was resized; C{False} if not.        
        """
        return False


    ###  calls from Transport


    def _set_transport(self, transport):
        self.transport = transport

    def _set_window(self, window_size, max_packet_size):
        self.in_window_size = window_size
        self.in_max_packet_size = max_packet_size
        # threshold of bytes we receive before we bother to send a window update
        self.in_window_threshold = window_size // 10
        self.in_window_sofar = 0
        
    def _set_remote_channel(self, chanid, window_size, max_packet_size):
        self.remote_chanid = chanid
        self.out_window_size = window_size
        self.out_max_packet_size = max_packet_size
        self.active = 1

    def _request_success(self, m):
        self._log(DEBUG, 'Sesch channel %d request ok' % self.chanid)
        return

    def _request_failed(self, m):
        self.close()

    def _feed(self, m):
        s = m.get_string()
        try:
            self.lock.acquire()
            self._log(DEBUG, 'fed %d bytes' % len(s))
            if self.pipe_wfd != None:
                self._feed_pipe(s)
            else:
                self.in_buffer += s
                self.in_buffer_cv.notifyAll()
            self._log(DEBUG, '(out from feed)')
        finally:
            self.lock.release()

    def _window_adjust(self, m):
        nbytes = m.get_int()
        try:
            self.lock.acquire()
            self._log(DEBUG, 'window up %d' % nbytes)
            self.out_window_size += nbytes
            self.out_buffer_cv.notifyAll()
        finally:
            self.lock.release()

    def _handle_request(self, m):
        key = m.get_string()
        want_reply = m.get_boolean()
        ok = False
        if key == 'exit-status':
            self.exit_status = m.get_int()
            ok = True
        elif key == 'xon-xoff':
            # ignore
            ok = True
        elif key == 'pty-req':
            term = m.get_string()
            width = m.get_int()
            height = m.get_int()
            pixelwidth = m.get_int()
            pixelheight = m.get_int()
            modes = m.get_string()
            ok = self.check_pty_request(term, width, height, pixelwidth, pixelheight, modes)
        elif key == 'shell':
            ok = self.check_shell_request()
        elif key == 'subsystem':
            name = m.get_string()
            ok = self.check_subsystem_request(name)
        elif key == 'window-change':
            width = m.get_int()
            height = m.get_int()
            pixelwidth = m.get_int()
            pixelheight = m.get_int()
            ok = self.check_window_change_request(width, height, pixelwidth, pixelheight)
        else:
            self._log(DEBUG, 'Unhandled channel request "%s"' % key)
            ok = False
        if want_reply:
            m = Message()
            if ok:
                m.add_byte(chr(MSG_CHANNEL_SUCCESS))
            else:
                m.add_byte(chr(MSG_CHANNEL_FAILURE))
            m.add_int(self.remote_chanid)
            self.transport._send_message(m)

    def _handle_eof(self, m):
        try:
            self.lock.acquire()
            if not self.eof_received:
                self.eof_received = 1
                self.in_buffer_cv.notifyAll()
                if self.pipe_wfd != None:
                    os.close(self.pipe_wfd)
                    self.pipe_wfd = None
        finally:
            self.lock.release()
        self._log(DEBUG, 'EOF received')

    def _handle_close(self, m):
        self.close()
        try:
            self.lock.acquire()
            self.in_buffer_cv.notifyAll()
            self.out_buffer_cv.notifyAll()
            if self.pipe_wfd != None:
                os.close(self.pipe_wfd)
                self.pipe_wfd = None
        finally:
            self.lock.release()


    ###  internals...


    def _log(self, level, msg):
        self.logger.log(level, msg)

    def _set_closed(self):
        # you are holding the lock.
        self.closed = True
        self.in_buffer_cv.notifyAll()
        self.out_buffer_cv.notifyAll()

    def _send_eof(self):
        if self.eof_sent:
            return
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_EOF))
        m.add_int(self.remote_chanid)
        self.transport._send_message(m)
        self.eof_sent = 1
        self._log(DEBUG, 'EOF sent')
        return

    def _feed_pipe(self, data):
        "you are already holding the lock"
        if len(self.in_buffer) > 0:
            self.in_buffer += data
            return
        try:
            n = os.write(self.pipe_wfd, data)
            if n < len(data):
                # at least on linux, this will never happen, as the writes are
                # considered atomic... but just in case.
                self.in_buffer = data[n:]
            self._check_add_window(n)
            self.in_buffer_cv.notifyAll()
            return
        except OSError, e:
            pass
        if len(data) > 1:
            # try writing just one byte then
            x = data[0]
            data = data[1:]
            try:
                os.write(self.pipe_wfd, x)
                self.in_buffer = data
                self._check_add_window(1)
                self.in_buffer_cv.notifyAll()
                return
            except OSError, e:
                data = x + data
        # pipe is very full
        self.in_buffer = data
        self.in_buffer_cv.notifyAll()

    def _read_pipe(self, nbytes):
        "you are already holding the lock"
        try:
            x = os.read(self.pipe_rfd, nbytes)
            if len(x) > 0:
                self._push_pipe(len(x))
                return x
        except OSError, e:
            pass
        # nothing in the pipe
        if self.closed or self.eof_received:
            return ''
        # should we block?
        if self.timeout == 0.0:
            raise socket.timeout()
        # loop here in case we get woken up but a different thread has grabbed everything in the buffer
        timeout = self.timeout
        while not self.closed and not self.eof_received:
            then = time.time()
            self.in_buffer_cv.wait(timeout)
            if timeout != None:
                timeout -= time.time() - then
                if timeout <= 0.0:
                    raise socket.timeout()
            try:
                x = os.read(self.pipe_rfd, nbytes)
                if len(x) > 0:
                    self._push_pipe(len(x))
                    return x
            except OSError, e:
                pass
        pass

    def _push_pipe(self, nbytes):
        # successfully read N bytes from the pipe, now re-feed the pipe if necessary
        # (assumption: the pipe can hold as many bytes as were read out)
        if len(self.in_buffer) == 0:
            return
        if len(self.in_buffer) <= nbytes:
            os.write(self.pipe_wfd, self.in_buffer)
            self.in_buffer = ''
            return
        x = self.in_buffer[:nbytes]
        self.in_buffer = self.in_buffer[nbytes:]
        os.write(self.pipd_wfd, x)

    def _unlink(self):
        if self.closed or not self.active:
            return
        try:
            self.lock.acquire()
            self._set_closed()
            self.transport._unlink_channel(self.chanid)
        finally:
            self.lock.release()

    def _check_add_window(self, n):
        # already holding the lock!
        if self.closed or self.eof_received or not self.active:
            return
        self._log(DEBUG, 'addwindow %d' % n)
        self.in_window_sofar += n
        if self.in_window_sofar > self.in_window_threshold:
            self._log(DEBUG, 'addwindow send %d' % self.in_window_sofar)
            m = Message()
            m.add_byte(chr(MSG_CHANNEL_WINDOW_ADJUST))
            m.add_int(self.remote_chanid)
            m.add_int(self.in_window_sofar)
            self.transport._send_message(m)
            self.in_window_sofar = 0


class ChannelFile (BufferedFile):
    """
    A file-like wrapper around L{Channel}.  A ChannelFile is created by calling
    L{Channel.makefile} and doesn't have the non-portable side effect of
    L{Channel.fileno}.

    @bug: To correctly emulate the file object created from a socket's
    C{makefile} method, a L{Channel} and its C{ChannelFile} should be able to
    be closed or garbage-collected independently.  Currently, closing the
    C{ChannelFile} does nothing but flush the buffer.
    """

    def __init__(self, channel, mode = 'r', bufsize = -1):
        self.channel = channel
        BufferedFile.__init__(self)
        self._set_mode(mode, bufsize)

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.

        @rtype: string
        """
        return '<paramiko.ChannelFile from ' + repr(self.channel) + '>'

    def _read(self, size):
        return self.channel.recv(size)

    def _write(self, data):
        self.channel.sendall(data)
        return len(data)


# vim: set shiftwidth=4 expandtab :
