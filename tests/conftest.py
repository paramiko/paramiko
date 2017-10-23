import logging
import os
import threading

import pytest
from paramiko import RSAKey, SFTPServer, SFTP, Transport

from .loop import LoopSocket
from .stub_sftp import StubServer, StubSFTPServer
from .util import _support


# TODO: not a huge fan of conftest.py files, see if we can move these somewhere
# 'nicer'.


# Perform logging by default; pytest will capture and thus hide it normally,
# presenting it on error/failure.
# Also make sure to set up timestamping for more sanity when debugging.
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(relativeCreated)s]\t%(levelname)s:%(name)s:%(message)s",
    datefmt="%H:%M:%S",
)


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


@pytest.fixture(scope='session')
def sftp_server():
    """
    Set up an in-memory SFTP server thread. Yields the client Transport/socket.

    The resulting client Transport (along with all the server components) will
    be the same object throughout the test session; the `sftp` fixture then
    creates new higher level client objects wrapped around the client
    Transport, as necessary.
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
    # Server setup
    event = threading.Event()
    server = StubServer()
    ts.set_subsystem_handler('sftp', SFTPServer, StubSFTPServer)
    ts.start_server(event, server)
    # Wait (so client has time to connect? Not sure. Old.)
    event.wait(1.0)
    # Make & yield connection.
    tc.connect(username='slowdive', password='pygmalion')
    yield tc
    # TODO: any need for shutdown? Why didn't old suite do so? Or was that the
    # point of the "join all threads from threading module" crap in test.py?


@pytest.fixture
def sftp(sftp_server):
    """
    Yield an SFTP client connected to the global in-session SFTP server thread.
    """
    # Client setup
    client = SFTP.from_transport(sftp_server)
    # Work in 'remote' folder setup (as it wants to use the client)
    # TODO: how cleanest to make this available to tests? Doing it this way is
    # marginally less bad than the previous 'global'-using setup, but not by
    # much?
    client.FOLDER = make_sftp_folder(client)
    # Yield client to caller
    yield client
    # Clean up
    # TODO: many tests like to close the client; to match old test suite
    # behavior we'd need to recreate the entire client? Possibly better to just
    # make the "it runs locally, dumbass" explicit & then just use stdlib to
    # clean up?
    #client.rmdir(client.FOLDER)
