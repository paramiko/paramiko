#!/usr/bin/python

"""
Sample script showing how to do local port forwarding over paramiko.

This script connects to the requested SSH server and sets up local port
forwarding (the openssh -L option) from a local port through a tunneled
connection to a destination reachable from the SSH server machine.

It uses SocketServer and select, so may not work on Windows.
"""

import sys
import os
import socket
import select
import SocketServer
import getpass
import base64
from optparse import OptionParser

import paramiko

DEFAULT_PORT = 4000
SSH_PORT = 22
VERBOSE = True
READPASS = False


class ForwardServer (SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    

class Handler (SocketServer.BaseRequestHandler):

    def handle(self):
        try:
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   (self.chain_host, self.chain_port),
                                                   self.request.getpeername())
        except Exception, e:
            verbose('Incoming request to %s:%d failed: %s' % (self.chain_host,
                                                              self.chain_port,
                                                              repr(e)))
            return

        verbose('Connected!  Tunnel open.')
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
        chan.close()
        self.request.close()
        verbose('Tunnel closed.')


def forward_tunnel(local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander (Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
    ForwardServer(('', local_port), SubHander).serve_forever()

def load_host_keys():
    filename = os.path.expanduser('~/.ssh/known_hosts')
    keys = {}
    try:
        f = open(filename, 'r')
    except Exception, e:
        print '*** Unable to open host keys file (%s)' % filename
        return
    for line in f:
        keylist = line.split(' ')
        if len(keylist) != 3:
            continue
        hostlist, keytype, key = keylist
        hosts = hostlist.split(',')
        for host in hosts:
            if not keys.has_key(host):
                keys[host] = {}
            keys[host][keytype] = base64.decodestring(key)
    f.close()
    return keys

def find_default_key_file():
    filename = os.path.expanduser('~/.ssh/id_rsa')
    if os.access(filename, os.R_OK):
        return filename
    filename = os.path.expanduser('~/.ssh/id_dsa')
    if os.access(filename, os.R_OK):
        return filename
    return ''

def verbose(s):
    if VERBOSE:
        print s


#####


parser = OptionParser(usage='usage: %prog [options] <remote-addr>:<remote-port>',
                      version='%prog 1.0')
parser.add_option('-q', '--quiet', action='store_false', dest='verbose', default=VERBOSE,
                  help='squelch all informational output')
parser.add_option('-l', '--local-port', action='store', type='int', dest='port',
                  default=DEFAULT_PORT,
                  help='local port to forward (default: %d)' % DEFAULT_PORT)
parser.add_option('-r', '--host', action='store', type='string', dest='ssh_host',
                  help='SSH host to tunnel through (required)')
parser.add_option('-p', '--port', action='store', type='int', dest='ssh_port', default=SSH_PORT,
                  help='SSH port to tunnel through (default: %d)' % SSH_PORT)
parser.add_option('-u', '--user', action='store', type='string', dest='user',
                  default=getpass.getuser(),
                  help='username for SSH authentication (default: %s)' % getpass.getuser())
parser.add_option('-K', '--key', action='store', type='string', dest='keyfile',
                  default=find_default_key_file(),
                  help='private key file to use for SSH authentication')
parser.add_option('', '--no-key', action='store_false', dest='use_key', default=True,
                  help='don\'t look for or use a private key file')
parser.add_option('-P', '--password', action='store_true', dest='readpass', default=READPASS,
                  help='read password (for key or password auth) from stdin')
options, args = parser.parse_args()

VERBOSE = options.verbose
READPASS = options.readpass


if len(args) != 1:
    parser.error('Incorrect number of arguments.')
remote_host = args[0]
if ':' not in remote_host:
    parser.error('Remote port missing.')
remote_host, remote_port = remote_host.split(':', 1)
try:
    remote_port = int(remote_port)
except:
    parser.error('Remote port must be a number.')

if not options.ssh_host:
    parser.error('SSH host is required.')
if ':' in options.ssh_host:
    options.ssh_host, options.ssh_port = options.ssh_host.split(':', 1)
    try:
        options.ssh_port = int(options.ssh_port)
    except:
        parser.error('SSH port must be a number.')

host_keys = load_host_keys()
if not host_keys.has_key(options.ssh_host):
    print '*** Warning: no host key for %s' % options.ssh_host
    expected_host_key_type = None
    expected_host_key = None
else:
    expected_host_key_type = host_keys[options.ssh_host].keys()[0]
    expected_host_key = host_keys[options.ssh_host][expected_host_key_type]

key = None
password = None
if options.use_key:
    try:
        key = paramiko.RSAKey.from_private_key_file(options.keyfile)
    except paramiko.PasswordRequiredException:
        if not READPASS:
            print '*** Password needed for keyfile (use -P): %s' % options.keyfile
            sys.exit(1)
        key_password = raw_input()
        try:
            key = paramiko.RSAKey.from_private_key_file(options.keyfile, key_password)
        except:
            print '*** Unable to read keyfile: %s' % options.keyfile
            sys.exit(1)
    except:
        pass

if key is None:
    # try reading a password then
    if not READPASS:
        print '*** Either a valid private key or password is required (use -K or -P).'
        sys.exit(1)
    password = raw_input()

verbose('Connecting to ssh host %s:%d ...' % (options.ssh_host, options.ssh_port))

transport = paramiko.Transport((options.ssh_host, options.ssh_port))
transport.connect(hostkeytype=expected_host_key_type,
                  hostkey=expected_host_key,
                  username=options.user,
                  password=password,
                  pkey=key)

verbose('Now forwarding port %d to %s:%d ...' % (options.port, remote_host, remote_port))

try:
    forward_tunnel(options.port, remote_host, remote_port, transport)
except KeyboardInterrupt:
    print 'Port forwarding stopped.'
    sys.exit(0)
