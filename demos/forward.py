#!/usr/bin/env python

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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Sample script showing how to do local port forwarding over paramiko.

This script connects to the requested SSH server and sets up local port
forwarding (the openssh -L option) from a local port through a tunneled
connection to a destination reachable from the SSH server machine.
"""

import getpass
import os
import socket
import select
from threading import Thread
try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

import sys
from optparse import OptionParser

import paramiko

SSH_PORT = 22
DEFAULT_PORT = 4000

g_verbose = True

class ForwardServer(SocketServer.ThreadingTCPServer,object):
    """
    Use ForwardServer in two ways:

    1. Call run() directly to start the forwarding.

        ForwardServer(...).run()

       In this usage pattern, the thread calling run() will be blocked until stop() is called from another thread.

    2. Use "with" statement to start server in a daemon thread.

        with ForwardServer(...) as serv:
            # Use the forwarded port

       In this usage pattern, the thread creating the server is not blocked and so can do something useful with the forwarded port.
       The server will be automatically stopped at the end of the with block.
    """
    def __init__(self, local_port, remote_host, remote_port, ssh_transport):
        # Save these for use by Handler class.
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.ssh_transport = ssh_transport
        super(ForwardServer, self).__init__(('', local_port), Handler)
        self.daemon_threads = True
        self.allow_reuse_address = True
        self.th = None

    def run(self):
        self.serve_forever()

    def stop(self):
        self.shutdown()
        self.socket.close()

    def join(self):
        if self.th:
            # Workaround for Thread.join() prevents KeyboardInterrupt from getting raised.
            while self.th.is_alive():
                self.th.join(0.1)

    def __enter__(self):
        self.th = Thread(target=self.run)
        self.th.daemon = True
        self.th.start()
        return self

    def __exit__(self, exc, val, trace):
        self.stop()

class Handler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.server.ssh_transport.open_channel('direct-tcpip',
                                                          (self.server.remote_host, self.server.remote_port),
                                                          self.request.getpeername())
        except Exception as e:
            verbose('Incoming request to %s:%d failed: %s' % (self.server.remote_host,
                                                              self.server.remote_port,
                                                              repr(e)))
            return
        if chan is None:
            verbose('Incoming request to %s:%d was rejected by the SSH server.' %
                    (self.server.remote_host, self.server.remote_port))
            return

        verbose('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(),
                                                            chan.getpeername(),
                                                            (self.server.remote_host, self.server.remote_port)))
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)
                
        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        verbose('Tunnel closed from %r' % (peername,))

def verbose(s):
    if g_verbose:
        print(s)


HELP = """\
Set up a forward tunnel across an SSH server, using paramiko. A local port
(given with -p) is forwarded across an SSH session to an address:port from
the SSH server. This is similar to the openssh -L option.
"""


def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(':', 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def parse_options():
    global g_verbose
    
    parser = OptionParser(usage='usage: %prog [options] <ssh-server>[:<server-port>]',
                          version='%prog 1.0', description=HELP)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose', default=True,
                      help='squelch all informational output')
    parser.add_option('-p', '--local-port', action='store', type='int', dest='port',
                      default=DEFAULT_PORT,
                      help='local port to forward (default: %d)' % DEFAULT_PORT)
    parser.add_option('-u', '--user', action='store', type='string', dest='user',
                      default=getpass.getuser(),
                      help='username for SSH authentication (default: %s)' % getpass.getuser())
    parser.add_option('-K', '--key', action='store', type='string', dest='keyfile',
                      default=None,
                      help='private key file to use for SSH authentication')
    parser.add_option('', '--no-key', action='store_false', dest='look_for_keys', default=True,
                      help='don\'t look for or use a private key file')
    parser.add_option('-P', '--password', action='store_true', dest='readpass', default=False,
                      help='read password (for key or password auth) from stdin')
    parser.add_option('-r', '--remote', action='store', type='string', dest='remote', default=None, metavar='host:port',
                      help='remote host and port to forward to')
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error('Incorrect number of arguments.')
    if options.remote is None:
        parser.error('Remote address required (-r).')
    
    g_verbose = options.verbose
    server_host, server_port = get_host_port(args[0], SSH_PORT)
    remote_host, remote_port = get_host_port(options.remote, SSH_PORT)
    return options, (server_host, server_port), (remote_host, remote_port)


def main():
    options, server, remote = parse_options()
    
    password = None
    if options.readpass:
        password = getpass.getpass('Enter SSH password: ')
    
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose('Connecting to ssh host %s:%d ...' % (server[0], server[1]))
    try:
        client.connect(server[0], server[1], username=options.user, key_filename=options.keyfile,
                       look_for_keys=options.look_for_keys, password=password)
    except Exception as e:
        print('*** Failed to connect to %s:%d: %r' % (server[0], server[1], e))
        sys.exit(1)

    verbose('Now forwarding port %d to %s:%d ...' % (options.port, remote[0], remote[1]))

    try:
        #ForwardServer(options.port, remote[0], remote[1], client.get_transport()).run()
        with ForwardServer(options.port, remote[0], remote[1], client.get_transport()) as serv:
            serv.join()
    except KeyboardInterrupt:
        print('C-c: Port forwarding stopped.')
        sys.exit(0)


if __name__ == '__main__':
    main()
