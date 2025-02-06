"""An example that shows an interactive terminal

$ ssh -p 2200 foo@localhost
The authenticity of host '[localhost]:2200 ([127.0.0.1]:2200)' can't be established.
RSA key fingerprint is SHA256:OhNL391d/beeFnxxg18AwWVYTAHww+D4djEE7Co0Yng.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[localhost]:2200' (RSA) to the list of known hosts.
foo@localhost's password: 
PTY allocation request failed on channel 0
Example Command Shell
# ipconfig -l
Fake host at 127.0.0.1
    additional config 00:00:00:11:11:11
# log test
Logged test
# exit
Connection to localhost closed.
$
$ ssh -p 2200 foo@localhost "ipconfig -l"
foo@localhost's password: 
Fake host at 127.0.0.1
    additional config 00:00:00:11:11:11
Connection to localhost closed by remote host.

"""

import base64
from binascii import hexlify
import os
import socket
import sys
import threading

import paramiko
from paramiko.py3compat import b, u, decodebytes

import cmd


class SimpleShell(cmd.Cmd):
    def __init__(self, pipes=None):
        if pipes:
            super(SimpleShell, self).__init__(stdin=pipes, stdout=pipes)
        else:
            super(SimpleShell, self).__init__()

        self.use_rawinput = False

        self.intro = "Example Command Shell"
        self.prompt = "# "

    def do_ipconfig(self, line):
        self.stdout.write("Fake host at 127.0.0.1\n")
        if "-l" in line or "--long" in line:
            self.stdout.write("    additional config 00:00:00:11:11:11\n")

    def do_log(self, line):
        self.stdout.write("Logged {}\n".format(line))

    def do_EOF(self, line):
        return True

    def do_exit(self, line):
        return True


# setup logging
paramiko.util.log_to_file("server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
# host_key = paramiko.DSSKey(filename='test_dss.key')

print("Read key: " + u(hexlify(host_key.get_fingerprint())))


class Session(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.exec = False
        self.shell = False

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == "foo") and (password == "bar"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    # Removing this causes the client to echo commands back
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
        try:
            cf = channel.makefile("rwU")
            s = SimpleShell(pipes=cf)
            s.onecmd(command.decode())
        except Exception as e:
            print(e)
        channel.close()
        self.event.set()
        return True


class Server(object):
    def __init__(self, port=2200):
        self.port = port

    def start_serving(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self.port))

        self.accept_connections(sock)

    def accept_connections(self, sock):
        sock.listen(100)
        while True:
            print("Listening for connection ...")
            client, addr = sock.accept()
            self.process_session(client)
            client.close()

    def process_session(self, client):
        print("Got a connection!")
        t = paramiko.Transport(client)
        t.add_server_key(host_key)
        session = Session()

        try:
            t.start_server(server=session)
        except paramiko.SSHException:
            sys.stderr.write("Session Negotiation Failed")

        channel = self.complete_auth(t)
        self.use_session(session, channel)

    def complete_auth(self, transport):
        channel = transport.accept(20)
        if channel is None:
            raise Exception("No channel created")
        print("Auth Complete")
        return channel

    def use_session(self, session, channel):
        session.event.wait(10)
        if not session.event.is_set():
            raise Exception(
                "Client never asked for a shell or sent a command."
            )

        if session.exec:
            return

        if session.shell:
            cf = channel.makefile("rwU")
            shell = SimpleShell(cf)
            shell.cmdloop()
            channel.close()


if __name__ == "__main__":
    s = Server()
    s.start_serving()
