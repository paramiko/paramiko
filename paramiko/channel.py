from message import Message
from paramiko import SSHException
from transport import MSG_CHANNEL_REQUEST, MSG_CHANNEL_CLOSE, MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_DATA, \
	MSG_CHANNEL_EOF, MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE

import time, threading, logging, socket, os
from logging import DEBUG


# this is ugly, and won't work on windows
def set_nonblocking(fd):
    import fcntl
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)


class Channel(object):
    """
    Abstraction for an SSH2 channel.
    """
    
    def __init__(self, chanid):
        self.chanid = chanid
        self.transport = None
        self.active = 0
        self.eof_received = 0
        self.eof_sent = 0
        self.in_buffer = ''
        self.timeout = None
        self.closed = 0
        self.lock = threading.Lock()
        self.in_buffer_cv = threading.Condition(self.lock)
        self.out_buffer_cv = threading.Condition(self.lock)
        self.name = str(chanid)
        self.logger = logging.getLogger('paramiko.chan.' + str(chanid))
        self.pipe_rfd = self.pipe_wfd = None

    def __repr__(self):
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

    def set_transport(self, transport):
        self.transport = transport

    def log(self, level, msg):
        self.logger.log(level, msg)

    def set_window(self, window_size, max_packet_size):
        self.in_window_size = window_size
        self.in_max_packet_size = max_packet_size
        # threshold of bytes we receive before we bother to send a window update
        self.in_window_threshold = window_size // 10
        self.in_window_sofar = 0
        
    def set_remote_channel(self, chanid, window_size, max_packet_size):
        self.remote_chanid = chanid
        self.out_window_size = window_size
        self.out_max_packet_size = max_packet_size
        self.active = 1

    def request_success(self, m):
        self.log(DEBUG, 'Sesch channel %d request ok' % self.chanid)
        return

    def request_failed(self, m):
        self.close()

    def feed(self, m):
        s = m.get_string()
        try:
            self.lock.acquire()
            self.log(DEBUG, 'fed %d bytes' % len(s))
            if self.pipe_wfd != None:
                self.feed_pipe(s)
            else:
                self.in_buffer += s
                self.in_buffer_cv.notifyAll()
            self.log(DEBUG, '(out from feed)')
        finally:
            self.lock.release()

    def window_adjust(self, m):
        nbytes = m.get_int()
        try:
            self.lock.acquire()
            self.log(DEBUG, 'window up %d' % nbytes)
            self.out_window_size += nbytes
            self.out_buffer_cv.notifyAll()
        finally:
            self.lock.release()

    def check_pty_request(self, term, width, height, pixelwidth, pixelheight, modes):
        "override me!  return True if a pty of the given dimensions (for shell access, usually) can be provided"
        return False

    def check_shell_request(self):
        "override me!  return True if shell access will be provided"
        return False

    def check_subsystem_request(self, name):
        "override me!  return True if the given subsystem can be provided"
        return False

    def check_window_change_request(self, width, height, pixelwidth, pixelheight):
        "override me!  return True if the pty was resized"
        return False

    def handle_request(self, m):
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
            self.log(DEBUG, 'Unhandled channel request "%s"' % key)
            ok = False
        if want_reply:
            m = Message()
            if ok:
                m.add_byte(chr(MSG_CHANNEL_SUCCESS))
            else:
                m.add_byte(chr(MSG_CHANNEL_FAILURE))
            m.add_int(self.remote_chanid)
            self.transport.send_message(m)

    def handle_eof(self, m):
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
        self.log(DEBUG, 'EOF received')

    def handle_close(self, m):
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


    # API for external use

    def get_pty(self, term='vt100', width=80, height=24):
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
        self.transport.send_message(m)

    def invoke_shell(self):
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('shell')
        m.add_boolean(1)
        self.transport.send_message(m)

    def exec_command(self, command):
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('exec')
        m.add_boolean(1)
        m.add_string(command)
        self.transport.send_message(m)

    def invoke_subsystem(self, subsystem):
        if self.closed or self.eof_received or self.eof_sent or not self.active:
            raise SSHException('Channel is not open')
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_REQUEST))
        m.add_int(self.remote_chanid)
        m.add_string('subsystem')
        m.add_boolean(1)
        m.add_string(subsystem)
        self.transport.send_message(m)

    def resize_pty(self, width=80, height=24):
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
        self.transport.send_message(m)

    def get_transport(self):
        return self.transport

    def set_name(self, name):
        self.name = name
        self.logger = logging.getLogger('paramiko.chan.' + name)

    def get_name(self):
        return self.name

    def send_eof(self):
        if self.eof_sent:
            return
        m = Message()
        m.add_byte(chr(MSG_CHANNEL_EOF))
        m.add_int(self.remote_chanid)
        self.transport.send_message(m)
        self.eof_sent = 1
        self.log(DEBUG, 'EOF sent')
        return


    # socket equivalency methods...

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def setblocking(self, blocking):
        if blocking:
            self.settimeout(None)
        else:
            self.settimeout(0.0)

    def close(self):
        try:
            self.lock.acquire()
            if self.active and not self.closed:
                self.send_eof()
                m = Message()
                m.add_byte(chr(MSG_CHANNEL_CLOSE))
                m.add_int(self.remote_chanid)
                self.transport.send_message(m)
                self.closed = 1
                self.transport.unlink_channel(self.chanid)
        finally:
            self.lock.release()

    def recv_ready(self):
        "doesn't work if you've called fileno()"
        try:
            self.lock.acquire()
            if len(self.in_buffer) == 0:
                return 0
            return 1
        finally:
            self.lock.release()

    def recv(self, nbytes):
        out = ''
        try:
            self.lock.acquire()
            if self.pipe_rfd != None:
                # use the pipe
                return self.read_pipe(nbytes)
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
            self.check_add_window(len(out))
        finally:
            self.lock.release()
        return out

    def send(self, s):
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
            self.transport.send_message(m)
            self.out_window_size -= size
        finally:
            self.lock.release()
        return size

    def sendall(self, s):
        while s:
            if self.closed:
                # this doesn't seem useful, but it is the documented behavior of Socket
                raise socket.error('Socket is closed')
            sent = self.send(s)
            s = s[sent:]
        return None

    def makefile(self, *params):
        return ChannelFile(*([self] + list(params)))

    def fileno(self):
        """
        returns an OS-level fd which can be used for polling and reading (but
        NOT for writing).  this is primarily to allow python's \"select\" module
        to work.  the first time this function is called, a pipe is created to
        simulate real OS-level fd behavior.  because of this, two actual fds are
        created: one to return and one to feed.  this may be inefficient if you
        plan to use many fds.

        the channel's receive window will be updated as data comes in, not as
        you read it, so if you fail to poll the channel often enough, it may
        block ALL channels across the transport.
        """
        try:
            self.lock.acquire()
            if self.pipe_rfd != None:
                return self.pipe_rfd
            # create the pipe and feed in any existing data
            self.pipe_rfd, self.pipe_wfd = os.pipe()
            set_nonblocking(self.pipe_wfd)
            set_nonblocking(self.pipe_rfd)
            if len(self.in_buffer) > 0:
                x = self.in_buffer
                self.in_buffer = ''
                self.feed_pipe(x)
            return self.pipe_rfd
        finally:
            self.lock.release()

    def shutdown(self, how):
        if (how == 0) or (how == 2):
            # feign "read" shutdown
            self.eof_received = 1
        if (how == 1) or (how == 2):
            self.send_eof()


    # internal use...

    def feed_pipe(self, data):
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
            self.check_add_window(n)
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
                self.check_add_window(1)
                self.in_buffer_cv.notifyAll()
                return
            except OSError, e:
                data = x + data
        # pipe is very full
        self.in_buffer = data
        self.in_buffer_cv.notifyAll()

    def read_pipe(self, nbytes):
        "you are already holding the lock"
        try:
            x = os.read(self.pipe_rfd, nbytes)
            if len(x) > 0:
                self.push_pipe(len(x))
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
                    self.push_pipe(len(x))
                    return x
            except OSError, e:
                pass
        pass

    def push_pipe(self, nbytes):
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

    def unlink(self):
        if self.closed or not self.active:
            return
        self.closed = 1
        self.transport.unlink_channel(self.chanid)

    def check_add_window(self, n):
        # already holding the lock!
        if self.closed or self.eof_received or not self.active:
            return
        self.log(DEBUG, 'addwindow %d' % n)
        self.in_window_sofar += n
        if self.in_window_sofar > self.in_window_threshold:
            self.log(DEBUG, 'addwindow send %d' % self.in_window_sofar)
            m = Message()
            m.add_byte(chr(MSG_CHANNEL_WINDOW_ADJUST))
            m.add_int(self.remote_chanid)
            m.add_int(self.in_window_sofar)
            self.transport.send_message(m)
            self.in_window_sofar = 0


class ChannelFile(object):
    """
    A file-like wrapper around Channel.
    Doesn't have the non-portable side effect of Channel.fileno().
    XXX Todo: the channel and its file-wrappers should be able to be closed or
    garbage-collected independently, for compatibility with real sockets and
    their file-wrappers. Currently, closing does nothing but flush the buffer.
    """

    def __init__(self, channel, mode = "r", buf_size = -1):
        self.channel = channel
        self.mode = mode
        if buf_size <= 0:
            self.buf_size = 1024
            self.line_buffered = 0
        elif buf_size == 1:
            self.buf_size = 1
            self.line_buffered = 1
        else:
            self.buf_size = buf_size
            self.line_buffered = 0
        self.wbuffer = ""
        self.rbuffer = ""
        self.readable = ("r" in mode)
        self.writable = ("w" in mode) or ("+" in mode) or ("a" in mode)
        self.universal_newlines = ('U' in mode)
        self.binary = ("b" in mode)
        self.at_trailing_cr = False
        self.name = '<file from ' + repr(self.channel) + '>'
        self.newlines = None
        self.softspace = False

    def __repr__(self):
        return '<paramiko.ChannelFile from ' + repr(self.channel) + '>'

    def __iter__(self):
        return self

    def next(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def write(self, str):
        if not self.writable:
            raise IOError("file not open for writing")
        if self.buf_size == 0 and not self.line_buffered:
            self.channel.sendall(str)
            return
        self.wbuffer += str
        if self.line_buffered:
            last_newline_pos = self.wbuffer.rfind("\n")
            if last_newline_pos >= 0:
                self.channel.sendall(self.wbuffer[:last_newline_pos+1])
                self.wbuffer = self.wbuffer[last_newline_pos+1:]
        else:
            if len(self.wbuffer) >= self.buf_size:
                self.channel.sendall(self.wbuffer)
                self.wbuffer = ""
        return

    def writelines(self, sequence):
        for s in sequence:
            self.write(s)
            return

    def flush(self):
        self.channel.sendall(self.wbuffer)
        self.wbuffer = ""
        return

    def read(self, size = None):
        if not self.readable:
            raise IOError("file not open for reading")
        if size is None or size < 0:
            result = self.rbuffer
            self.rbuffer = ""
            while not self.channel.eof_received:
                new_data = self.channel.recv(65536)
                if not new_data:
                    break
                result += new_data
            return result
        if size <= len(self.rbuffer):
            result = self.rbuffer[:size]
            self.rbuffer = self.rbuffer[size:]
            return result
        while len(self.rbuffer) < size and not self.channel.eof_received:
            new_data = self.channel.recv(max(self.buf_size, size-len(self.rbuffer)))
            if not new_data:
                break
            self.rbuffer += new_data
        result = self.rbuffer[:size]
        self.rbuffer[size:]
        return result

    def readline(self, size=None):
        line = self.rbuffer
        while 1:
            if self.at_trailing_cr and (len(line) > 0):
                if line[0] == '\n':
                    line = line[1:]
                self.at_trailing_cr = False
            if self.universal_newlines:
                if ('\n' in line) or ('\r' in line):
                    break
            else:
                if '\n' in line:
                    break
            if size >= 0:
                if len(line) >= size:
                    # truncate line and return
                    self.rbuffer = line[size:]
                    line = line[:size]
                    return line
                n = size - len(line)
            else:
                n = 64
            new_data = self.channel.recv(n)
            if not new_data:
                self.rbuffer = ''
                return line
            line += new_data
        # find the newline
        pos = line.find('\n')
        if self.universal_newlines:
            rpos = line.find('\r')
            if (rpos >= 0) and ((rpos < pos) or (pos < 0)):
                pos = rpos
        xpos = pos + 1
        if (line[pos] == '\r') and (xpos < len(line)) and (line[xpos] == '\n'):
            xpos += 1
        self.rbuffer = line[xpos:]
        lf = line[pos:xpos]
        line = line[:xpos]
        if (len(self.rbuffer) == 0) and (lf == '\r'):
            # we could read the line up to a '\r' and there could still be a
            # '\n' following that we read next time.  note that and eat it.
            self.at_trailing_cr = True
        # silliness about tracking what kinds of newlines we've seen
        if self.newlines is None:
            self.newlines = lf
        elif (type(self.newlines) is str) and (self.newlines != lf):
            self.newlines = (self.newlines, lf)
        elif lf not in self.newlines:
            self.newlines += (lf,)
        return line

    def readlines(self, sizehint = None):
        lines = []
        while 1:
            line = self.readline()
            if not line:
                break
            lines.append(line)
        return lines

    def xreadlines(self):
        return self

    def close(self):
        self.flush()
        return

# vim: set shiftwidth=4 expandtab :
