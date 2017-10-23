import os
import threading

import pytest
from paramiko import RSAKey, SFTPServer, SFTP, Transport

from .loop import LoopSocket
from .stub_sftp import StubServer, StubSFTPServer
from .util import _support


# TODO: not a huge fan of conftest.py files, see if we can move these somewhere
# 'nicer'.


def make_sftp_folder(client):
    """
    Create some non-existing, new folder on the given SFTP connection.
    """
    path = os.environ.get('TEST_FOLDER', 'temp-testing000')
    # TODO: this is disgusting and old, replace with something smarter/simpler
    for i in range(1000):
        path = path[:-3] + '%03d' % i
        try:
            client.mkdir(path)
            return path
        except (IOError, OSError):
            pass


# TODO: apply at module or session level
# TODO: roll in SFTP folder setup and teardown?
# NOTE: This is defined here for use by both SFTP (normal & 'big') suites.
@pytest.fixture
def sftp():
    """
    Set up an in-memory SFTP server, returning its corresponding SFTPClient.
    """
    # Sockets & transports
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    # Auth
    host_key = RSAKey.from_private_key_file(_support('test_rsa.key'))
    ts.add_server_key(host_key)
    # Server & client setup
    event = threading.Event()
    server = StubServer()
    ts.set_subsystem_handler('sftp', SFTPServer, StubSFTPServer)
    ts.start_server(event, server)
    tc.connect(username='slowdive', password='pygmalion')
    event.wait(1.0)
    client = SFTP.from_transport(tc)
    # Work in 'remote' folder setup (as it wants to use the client)
    # TODO: how cleanest to make this available to tests? Doing it this way is
    # marginally less bad than the previous 'global'-using setup, but not by
    # much?
    client.FOLDER = make_sftp_folder(client)
    # Yield client to caller
    yield client
    # Clean up
    client.rmdir(client.FOLDER)
