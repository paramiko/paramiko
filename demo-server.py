#!/usr/bin/python

import sys, os, socket, threading, logging, traceback
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
host_key.read_private_key_file('/home/robey/sshkey/ssh_host_rsa_key')

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
    t = secsh.Transport(client)
    t.add_server_key(host_key)
    t.ultra_debug = 1
    t.start_server(event)
    # print repr(t)
    event.wait(10)
    if not t.is_active():
        print '*** SSH negotiation failed.'
        sys.exit(1)
    # print repr(t)
except Exception, e:
    print '*** Caught exception: ' + str(e.__class__) + ': ' + str(e)
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)

