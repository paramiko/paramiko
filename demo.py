#!/usr/bin/python

import sys, os, socket, threading, getpass, logging, time, base64, select, termios, tty, traceback
import paramiko


#####   utility functions

def load_host_keys():
    filename = os.environ['HOME'] + '/.ssh/known_hosts'
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


#####   main demo

# setup logging
l = logging.getLogger("paramiko")
l.setLevel(logging.DEBUG)
if len(l.handlers) == 0:
    f = open('demo.log', 'w')
    lh = logging.StreamHandler(f)
    lh.setFormatter(logging.Formatter('%(levelname)-.3s [%(asctime)s] %(name)s: %(message)s', '%Y%m%d:%H%M%S'))
    l.addHandler(lh)


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
    keytype, hostkey = t.get_remote_server_key()
    if not keys.has_key(hostname):
        print '*** WARNING: Unknown host key!'
    elif not keys[hostname].has_key(keytype):
        print '*** WARNING: Unknown host key!'
    elif keys[hostname][keytype] != hostkey:
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
        key = paramiko.RSAKey()
        default_path = os.environ['HOME'] + '/.ssh/id_rsa'
        path = raw_input('RSA key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key.read_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('RSA key password: ')
            key.read_private_key_file(path, password)
        t.auth_publickey(username, key, event)
    elif auth == 'd':
        key = paramiko.DSSKey()
        default_path = os.environ['HOME'] + '/.ssh/id_dsa'
        path = raw_input('DSS key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key.read_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('DSS key password: ')
            key.read_private_key_file(path, password)
        t.auth_key(username, key, event)
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

