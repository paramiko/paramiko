#!/usr/bin/python

import sys, os, socket, threading, traceback, base64
import paramiko

# setup logging
paramiko.util.log_to_file('demo_server.log')

#host_key = paramiko.RSAKey()
#host_key.read_private_key_file('demo_rsa_key')

host_key = paramiko.DSSKey()
host_key.read_private_key_file('demo_dss_key')

print 'Read key: ' + paramiko.util.hexify(host_key.get_fingerprint())


class ServerTransport(paramiko.Transport):
    # 'data' is the output of base64.encodestring(str(key))
    data = 'AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hpfAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMCKDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iTUWT10hcuO4Ks8='
    good_pub_key = paramiko.RSAKey(data=base64.decodestring(data))

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return ServerChannel(chanid)
        return self.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == 'robey') and (password == 'foo'):
            return self.AUTH_SUCCESSFUL
        return self.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print 'Auth attempt with key: ' + paramiko.util.hexify(key.get_fingerprint())
        if (username == 'robey') and (key == self.good_pub_key):
            return self.AUTH_SUCCESSFUL
        return self.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'


class ServerChannel(paramiko.Channel):
    "Channel descendant that pretends to understand pty and shell requests"

    def __init__(self, chanid):
        paramiko.Channel.__init__(self, chanid)
        self.event = threading.Event()

    def check_pty_request(self, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_shell_request(self):
        self.event.set()
        return True


# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 2200))
except Exception, e:

    print '*** Bind failed: ' + str(e)
    traceback.print_exc()
    sys.exit(1)

try:
    sock.listen(100)
    print 'Listening for connection ...'
    client, addr = sock.accept()
except Exception, e:
    print '*** Listen/accept failed: ' + str(e)
    traceback.print_exc()
    sys.exit(1)

print 'Got a connection!'

try:
    event = threading.Event()
    t = ServerTransport(client)
    try:
        t.load_server_moduli()
    except:
        print '(Failed to load moduli -- gex will be unsupported.)'
        raise
    t.add_server_key(host_key)
    t.start_server(event)
    while 1:
        event.wait(0.1)
        if not t.is_active():
            print '*** SSH negotiation failed.'
            sys.exit(1)
        if event.isSet():
            break
    # print repr(t)

    # wait for auth
    chan = t.accept(20)
    if chan is None:
        print '*** No channel.'
        sys.exit(1)
    print 'Authenticated!'
    chan.event.wait(10)
    if not chan.event.isSet():
        print '*** Client never asked for a shell.'
        sys.exit(1)

    chan.send('\r\n\r\nWelcome to my dorky little BBS!\r\n\r\n')
    chan.send('We are on fire all the time!  Hooray!  Candy corn for everyone!\r\n')
    chan.send('Happy birthday to Robot Dave!\r\n\r\n')
    chan.send('Username: ')
    f = chan.makefile('rU')
    username = f.readline().strip('\r\n')
    chan.send('\r\nI don\'t like you, ' + username + '.\r\n')
    chan.close()

except Exception, e:
    print '*** Caught exception: ' + str(e.__class__) + ': ' + str(e)
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)

