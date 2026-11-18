#!/usr/bin/env python

# Copyright (C) 2020 Thomas Kent <tom@teeks99.com>
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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""Example paramiko ssh server running a custom shell

This example expands substantially upon paramiko's demo_server.py to
implement a shell similar to if a user were logging into a machine over
ssh.

The shell is implemented in SimpleShell using python's cmd module.
This can be readily extended to support any commands desired.

The shell is hooked up to the ServerLogger that logs each command and
response to a log file.

The Server listens across one or more sockets for TCP connections.
When one is received, it will start a thread to handle the processing
of commands from that client.

The ClientSession and ServerSession handle the setup, authentication,
and processing of the session. It will accept password or public key
authentication. It can handle shells or single-shot "exec" commands.

$ ssh -p 2200 foo@localhost
foo@localhost's password:
PTY allocation request failed on channel 0
p-sh$ ifconfig
lo:
    inet 127.0.0.1 netmask 255.0.0.0
    inet6 ::1 prefixlen 128
p-sh$ ls
directory   file.txt   secrets.txt
p-sh$ ls -l
dr-xr-xr-x 1 user user  123 Jan 1  1970  directory
-rw-rw-r-- 1 user user  123 Jan 1  1970  file.txt
-rw------- 1 user user  123 Jan 1  1970  secrets.txt
p-sh$
p-sh$ exit
Connection to localhost closed.


$ ssh -p 2200 foo@localhost ifconfig
foo@localhost's password:
lo:
    inet 127.0.0.1 netmask 255.0.0.0
    inet6 ::1 prefixlen 128

$ ssh -i user_rsa_key -p 2200 user@localhost
PTY allocation request failed on channel 0
p-sh$ ifconfig
lo:
    inet 127.0.0.1 netmask 255.0.0.0
    inet6 ::1 prefixlen 128
p-sh$

"""

import logging
import datetime
import os
import threading
import cmd
import base64
from binascii import hexlify
import socket
import sys
import traceback
from select import select

import paramiko
from paramiko.py3compat import b, u, decodebytes

logging_setup_mutex = threading.Lock()

logging_directory = "logs"
log_file_template = "session_{file_timestamp}.log"

# setup logging
# paramiko.util.log_to_file("server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
# host_key = paramiko.DSSKey(filename='test_dss.key')
print("Read key: " + u(hexlify(host_key.get_fingerprint())))

authorized_passwords = {"foo": "bar", "someone": "badpassword"}
authorized_keys = {"user": "user_rsa_key.pub"}

bind_to = [("", 2200)]

shutdown_commanded = False


class LoggingPipe:
    """Pipe needed to pull from the channel and log"""

    def __init__(self, logger, upstream_pipe):
        self.logger = logger
        self.upstream_pipe = upstream_pipe

    def write(self, buffer):
        self.logger.log_output(buffer)
        self.upstream_pipe.write(buffer)

    def readline(self):
        value = self.upstream_pipe.readline()
        self.logger.log_input(value)
        return value

    def flush(self):
        self.upstream_pipe.flush()


class ServerLogger:
    """Logs commands and responses to file"""

    def __init__(self):
        with logging_setup_mutex:

            self.current_command = None
            self.logger = logging.getLogger("ssh_server.commands")
            self.logger.setLevel(logging.INFO)
            stamp_format = "%Y%m%d-%H%M%S-%f"
            file_timestamp = datetime.datetime.now().strftime(stamp_format)
            if not os.path.isdir(logging_directory):
                os.makedirs(logging_directory)
            fh = logging.FileHandler(
                os.path.join(
                    logging_directory,
                    log_file_template.format(file_timestamp=file_timestamp),
                ),
                "w",
            )
            fh.setLevel(logging.INFO)
            formatter = logging.Formatter("%(asctime)s\n%(message)s")
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def close(self):
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)

    def upgrade_pipe(self, pipe):
        lp = LoggingPipe(self, pipe)
        return lp

    def start_command(self):
        self.current_command = ""

    def complete_command(self):
        self.logger.info(self.current_command)
        self.current_command = None

    def log_input(self, input):
        if self.current_command is not None:
            self.current_command += f"> {input}\n"

    def log_output(self, output):
        if self.current_command is not None:
            self.current_command += f"{output}\n"


class SimpleShell(cmd.Cmd):
    """Interactive shell providing command support

    Logs through the pipe for commands and responses.
    """

    def __init__(self, pipes=None):
        self.server_logger = ServerLogger()
        if pipes:
            logging_pipes = self.server_logger.upgrade_pipe(pipes)
            super(SimpleShell, self).__init__(
                stdin=logging_pipes, stdout=logging_pipes
            )
        else:
            super(SimpleShell, self).__init__()

        self.use_rawinput = False

        # self.intro = "Example Command Shell"
        self.prompt = "p-sh$ "

    def close(self):
        self.server_logger.close()

    def postloop(self):
        self.close()

    def precmd(self, line):
        self.server_logger.start_command()
        self.server_logger.log_input(line)
        return line

    def postcmd(self, stop, line):
        self.server_logger.complete_command()
        return stop

    def singleshot(self, command):
        self.server_logger.start_command()
        self.server_logger.log_input(command)

        self.onecmd(command)

        self.server_logger.complete_command()

    def do_ifconfig(self, line):
        self.stdout.write(
            "lo: \n"
            + "    inet 127.0.0.1 netmask 255.0.0.0\n"
            + "    inet6 ::1 prefixlen 128\n"
        )

    def do_ls(self, line):
        if "-l" in line:
            self.stdout.write(
                "dr-xr-xr-x 1 user user  123 Jan 1  1970  directory\n"
                + "-rw-rw-r-- 1 user user  123 Jan 1  1970  file.txt\n"
                + "-rw------- 1 user user  123 Jan 1  1970  secrets.txt\n"
            )
        else:
            self.stdout.write("directory   file.txt   secrets.txt\n")

    def emptyline(self):
        pass

    def do_EOF(self, line):
        return True

    def do_exit(self, line):
        return True


class SessionConnectionError(Exception):
    """Custom exception for ServerSessions that shouldn't kill the Server"""

    pass


class Server(object):
    """Handles TCP connections from clients

    This server can bind to multiple sockets and listen across all of
    them. For each connection from a client, the new socket is sent
    off to its own thread for processing.
    """

    def __init__(self):
        pass

    def start_serving(self):
        self.sockets = []

        for pair in bind_to:
            self._bind_socket(pair[0], pair[1])

        self.accept_connections()

        for sock in self.sockets:
            sock.close()

    def _bind_socket(self, address, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        sock.bind((address, port))
        self.sockets.append(sock)

    def accept_connections(self):
        threads = []
        for sock in self.sockets:
            sock.listen(100)
        print("Listening for connection ...")

        while not shutdown_commanded:
            try:
                # 1ms, how long before we loop and see an exception/shutdown
                timeout_sec = 0.001
                ready, _, _ = select(self.sockets, [], [], timeout_sec)
                if ready:
                    for s in ready:
                        self.new_connection_thread(s, threads)
            except KeyboardInterrupt:
                print("Closing Down")
                break

            self.remove_dead_threads(threads)

        self.close_all_sessions(threads)

    def new_connection_thread(self, sock, threads):
        client, addr = sock.accept()
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        s = ServerSession(client, addr)

        # If you want to run only one thread for debugging
        # s.run_synchronously()

        # Run each client in its own thread
        s.start()
        threads.append(s)

        print("Listen for a new connection...")

    def remove_dead_threads(self, threads):
        for t in threads[:]:
            if not t.is_alive():
                if t.raised_exception_info:
                    self.handle_thread_exception(t.raised_exception_info)
                threads.remove(t)

    def handle_thread_exception(self, exc_info):
        exc_type, exc_value, exc_tb = exc_info
        if exc_type is SessionConnectionError:
            print_exception(exc_info, "Session Connection Lost", False)
        else:
            raise exc_value.with_traceback(exc_tb)

    def close_all_sessions(self, threads):
        print("Shutting Down Server...")
        for t in threads[:]:
            t.close_transport()

        for t in threads[:]:
            t.join()

        self.remove_dead_threads(threads)


class ServerSession(threading.Thread):
    """Server side processing for each session initiated by a client

    Each time a channel closes (common for single-shot `exec` type
    commands), it will try to accept a new channel until the client
    disconnects.
    """

    def __init__(self, client, addr):
        threading.Thread.__init__(self)
        self.client = client
        self.addr = addr
        self.raised_exception_info = None
        self.t = None

    def run_synchronously(self):
        self.process_session()

    def run(self):
        try:
            self.process_session()
        except Exception:
            self.raised_exception_info = sys.exc_info()

    def process_session(self):
        sys.__stdout__.write(f"Session started for {self.addr}\n")
        sys.__stdout__.flush()
        self.t = paramiko.Transport(self.client)
        self.t.add_server_key(host_key)
        client_session = ClientSession()

        try:
            self.t.start_server(server=client_session)
        except paramiko.SSHException:
            sys.stderr.write("Session Negotiation Failed")

        while self.t.is_active():
            # Only supports one channel at a time, but keeps checking for more
            # after that channel is done.
            try:
                channel = self.complete_auth(self.t)
                self.use_session(client_session, channel)
            except SessionConnectionError:
                pass
        self.close_transport()

    def complete_auth(self, transport):
        channel = transport.accept(20)
        if channel is None:
            raise SessionConnectionError("No channel created")
        print("Auth Complete")
        return channel

    def use_session(self, client_session, channel):
        client_session.event.wait(10)
        if not client_session.event.is_set():
            raise SessionConnectionError(
                "Client never asked for a shell or sent a command."
            )

        cf = channel.makefile("rwU")
        shell = SimpleShell(pipes=cf)

        if client_session.exec:
            try:
                shell.singleshot(client_session.command.decode())
                shell.close()
            except Exception as e:
                print(e)

        elif client_session.shell:
            try:
                shell.cmdloop()
            except OSError as os_error:
                if os_error.args[0] == "Socket is closed":
                    raise SessionConnectionError("Socket is closed")
                else:
                    raise

        channel.close()

    def close_transport(self):
        if self.t.is_active():
            self.t.close()
            sys.__stdout__.write(f"Session ended for {self.addr}\n")
            sys.__stdout__.flush()


class ClientSession(paramiko.ServerInterface):
    """Authentication and setup for each client session"""

    def __init__(self):
        self.event = threading.Event()
        self.exec = False
        self.shell = False

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username in authorized_passwords:
            if password == authorized_passwords[username]:
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username in authorized_keys:
            auth_key = paramiko.PublicBlob.from_file(authorized_keys[username])
            if auth_key.key_blob == key.asbytes():
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    # Disabling this causes the shell to echo back inputs
    # def check_channel_pty_request(
    #    self, channel, term, width, height, pixelwidth, pixelheight, modes
    # ):
    #    return True

    def check_channel_shell_request(self, channel):
        self.shell = True
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec = True
        self.command = command
        self.event.set()
        return True


def print_exception(
    exc_info, log_message="Exception running ssh server", include_trace=True
):
    exc_type, exc_value, exc_tb = exc_info
    sys.__stdout__.write(log_message + ": Reason: " + str(exc_value) + "\n")
    if include_trace:
        tbe = traceback.TracebackException(exc_type, exc_value, exc_tb)
        sys.__stdout__.write("".join(tbe.format()))
    sys.__stdout__.flush()


if __name__ == "__main__":
    Server().start_serving()
