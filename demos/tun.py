#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
# Differences to demos/forward.py are in the Public Domain.
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
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Sample script showing how to do tunX VPN over paramiko.

On the target:
# ifconfig tun0 up 10.0.0.100 netmask 255.255.255.0 pointopoint 10.0.0.1
"""

import getpass
import os
import socket
import select
import SocketServer
import sys
from optparse import OptionParser
from scapy.all import *
from time import sleep, time
from struct import pack
from socket import AF_INET

sys.path = ['.'] + sys.path
import paramiko

SSH_PORT = 22

def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(':', 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def parse_options():
    parser = OptionParser(usage='usage: %prog [options] <ssh-server>[:<server-port>]',
                          version='%prog 1.0')
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
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error('Incorrect number of arguments.')
    
    server_host, server_port = get_host_port(args[0], SSH_PORT)
    return options, (server_host, server_port)


def main():
    options, server = parse_options()
    
    password = None
    if options.readpass:
        password = getpass.getpass('Enter SSH password: ')
    
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    try:
        client.connect(server[0], server[1], username=options.user, key_filename=options.keyfile,
                       look_for_keys=options.look_for_keys, password=password)
    except Exception, e:
        print '*** Failed to connect to %s:%d: %r' % (server[0], server[1], e)
        sys.exit(1)

    transport = client.get_transport()
    remote_tun = transport.open_channel('tun@openssh.com')

    try:
        while True:
            pkt = IP(dst = '10.0.0.100', src='10.0.0.1') / ICMP() / ('tun@' * 4)
            remote_tun.send( pack('@I', len(pkt)) + str(pkt) )
            print 'sent:', pkt.summary()

            now = time()
            rfd, _, _ = select([remote_tun], [], [], 3.0)

            if remote_tun in rfd:
                b = remote_tun.recv(1024)
                print 'incoming:', IP(str(b[4:])).summary()
                sleep(3 - (time() - now))
    except KeyboardInterrupt:
        print 'C-c: Port forwarding stopped.'

    client.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
