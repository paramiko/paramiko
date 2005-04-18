#!/usr/bin/python

# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
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
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import sys, os, socket, threading, getpass, time, base64, select, termios, tty, traceback
import paramiko


#####   utility functions

def load_host_keys():
    # this file won't exist on windows, but windows doesn't have a standard
    # location for this file anyway.
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
            if keytype == 'ssh-rsa':
                keys[host][keytype] = paramiko.RSAKey(data=base64.decodestring(key))
            elif keytype == 'ssh-dss':
                keys[host][keytype] = paramiko.DSSKey(data=base64.decodestring(key))
    f.close()
    return keys


#####   main demo

# setup logging
paramiko.util.log_to_file('demo.log')


username = ''
if len(sys.argv) > 1:
    hostname = sys.argv[1]
    if hostname.find('@') >= 0:
        username, hostname = hostname.split('@')
else:
    hostname = raw_input('Hostname: ')
if len(hostname) == 0:
    print '*** Hostname required.'
    sys.exit(1)
port = 22
if hostname.find(':') >= 0:
    hostname, portstr = hostname.split(':')
    port = int(portstr)

# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))
except Exception, e:
    print '*** Connect failed: ' + str(e)
    traceback.print_exc()
    sys.exit(1)

try:
    event = threading.Event()
    t = paramiko.Transport(sock)
    t.start_client(event)
    # print repr(t)
    event.wait(15)
    if not t.is_active():
        print '*** SSH negotiation failed.'
        sys.exit(1)
    # print repr(t)

    keys = load_host_keys()
    key = t.get_remote_server_key()
    if not keys.has_key(hostname):
        print '*** WARNING: Unknown host key!'
    elif not keys[hostname].has_key(key.get_name()):
        print '*** WARNING: Unknown host key!'
    elif keys[hostname][key.get_name()] != key:
        print '*** WARNING: Host key has changed!!!'
        sys.exit(1)
    else:
        print '*** Host key OK.'

    event.clear()

    # get username
    if username == '':
        default_username = getpass.getuser()
        username = raw_input('Username [%s]: ' % default_username)
        if len(username) == 0:
            username = default_username

    # ask for what kind of authentication to try
    default_auth = 'p'
    auth = raw_input('Auth by (p)assword, (r)sa key, or (d)ss key? [%s] ' % default_auth)
    if len(auth) == 0:
        auth = default_auth

    if auth == 'r':
        default_path = os.environ['HOME'] + '/.ssh/id_rsa'
        path = raw_input('RSA key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.RSAKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('RSA key password: ')
            key = paramiko.RSAKey.from_private_key_file(path, password)
        t.auth_publickey(username, key, event)
    elif auth == 'd':
        default_path = os.environ['HOME'] + '/.ssh/id_dsa'
        path = raw_input('DSS key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.DSSKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('DSS key password: ')
            key = paramiko.DSSKey.from_private_key_file(path, password)
        t.auth_publickey(username, key, event)
    else:
        pw = getpass.getpass('Password for %s@%s: ' % (username, hostname))
        t.auth_password(username, pw, event)

    event.wait(10)
    # print repr(t)
    if not t.is_authenticated():
        print '*** Authentication failed. :('
        t.close()
        sys.exit(1)

    chan = t.open_session()
    chan.get_pty()
    chan.invoke_shell()
    print '*** Here we go!'
    print

    try:
        oldtty = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

        while 1:
            r, w, e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    x = chan.recv(1024)
                    if len(x) == 0:
                        print
                        print '*** EOF\r\n',
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                # FIXME: reading 1 byte at a time is incredibly dumb.
                x = sys.stdin.read(1)
                if len(x) == 0:
                    print
                    print '*** Bye.\r\n',
                    break
                chan.send(x)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

    chan.close()
    t.close()

except Exception, e:
    print '*** Caught exception: ' + str(e.__class__) + ': ' + str(e)
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)

