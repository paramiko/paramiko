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

import sys, os, base64, getpass, socket, traceback, termios, tty, select
import paramiko


# setup logging
paramiko.util.log_to_file('demo_simple.log')

# get hostname
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


# get username
if username == '':
    default_username = getpass.getuser()
    username = raw_input('Username [%s]: ' % default_username)
    if len(username) == 0:
        username = default_username
password = getpass.getpass('Password for %s@%s: ' % (username, hostname))


# get host key, if we know one
hostkeytype = None
hostkey = None
try:
    hkeys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
except IOError:
    try:
        hkeys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
    except IOError:
        print '*** Unable to open host keys file'
        hkeys = {}

if hkeys.has_key(hostname):
    hostkeytype = hkeys[hostname].keys()[0]
    hostkey = hkeys[hostname][hostkeytype]
    print 'Using host key of type %s' % hostkeytype


# now, connect and use paramiko Transport to negotiate SSH2 across the connection
try:
    t = paramiko.Transport((hostname, port))
    t.connect(username=username, password=password, hostkey=hostkey)
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
                        print '\r\n*** EOF\r\n',
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
    print '*** Caught exception: %s: %s' % (e.__class__, e)
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
