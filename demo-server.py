#!/usr/bin/python

import sys, os, socket, threading, logging, traceback, time
import secsh

# setup logging
l = logging.getLogger("secsh")
l.setLevel(logging.DEBUG)
if len(l.handlers) == 0:
    f = open('demo-server.log', 'w')
    lh = logging.StreamHandler(f)
    lh.setFormatter(logging.Formatter('%(levelname)-.3s [%(asctime)s] %(name)s: %(message)s', '%Y%m%d:%H%M%S'))
    l.addHandler(lh)

host_key = secsh.RSAKey()
host_key.read_private_key_file('demo-host-key')


class ServerTransport(secsh.Transport):
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return secsh.Channel(chanid)
        return self.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == 'robey') and (password == 'foo'):
            return self.AUTH_SUCCESSFUL
        return self.AUTH_FAILED


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
    client, addr = sock.accept()
except Exception, e:
    print '*** Listen/accept failed: ' + str(e)
    traceback.print_exc()
    sys.exit(1)

try:
    event = threading.Event()
    t = ServerTransport(client)
    t.add_server_key(host_key)
    t.ultra_debug = 1
    t.start_server(event)
    # print repr(t)
    event.wait(10)
    if not t.is_active():
        print '*** SSH negotiation failed.'
        sys.exit(1)
    # print repr(t)

    chan = t.accept()
    time.sleep(2)
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

