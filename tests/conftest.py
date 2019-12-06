import logging
import os
import shutil
import threading

import pytest
from paramiko import SFTPServer, SFTP, Transport, load_private_key_file

from .loop import LoopSocket
from .stub_sftp import StubServer, StubSFTPServer
from .util import _support


# TODO: not a huge fan of conftest.py files, see if we can move these somewhere
# 'nicer'.


# Perform logging by default; pytest will capture and thus hide it normally,
# presenting it on error/failure. (But also allow turning it off when doing
# very pinpoint debugging - e.g. using breakpoints, so you don't want output
# hiding enabled, but also don't want all the logging to gum up the terminal.)
if not os.environ.get('DISABLE_LOGGING', False):
    logging.basicConfig(
        level=logging.DEBUG,
        # Also make sure to set up timestamping for more sanity when debugging.
        format="[%(relativeCreated)s]\t%(levelname)s:%(name)s:%(message)s",
        datefmt="%H:%M:%S",
    )


def make_sftp_folder():
    """
    Ensure expected target temp folder exists on the remote end.

    Will clean it out if it already exists.
    """
    # TODO: go back to using the sftp functionality itself for folder setup so
    # we can test against live SFTP servers again someday. (Not clear if anyone
    # is/was using the old capability for such, though...)
    # TODO: something that would play nicer with concurrent testing (but
    # probably e.g. using thread ID or UUIDs or something; not the "count up
    # until you find one not used!" crap from before...)
    # TODO: if we want to lock ourselves even harder into localhost-only
    # testing (probably not?) could use tempdir modules for this for improved
    # safety. Then again...why would someone have such a folder???
    path = os.environ.get('TEST_FOLDER', 'paramiko-test-target')
    # Forcibly nuke this directory locally, since at the moment, the below
    # fixtures only ever run with a locally scoped stub test server.
    shutil.rmtree(path, ignore_errors=True)
    # Then create it anew, again locally, for the same reason.
    os.mkdir(path)
    return path


@pytest.fixture  # (scope='session')
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
    host_key = load_private_key_file(_support('test_rsa.key'))
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
    client.FOLDER = make_sftp_folder()
    # Yield client to caller
    yield client
    # Clean up - as in make_sftp_folder, we assume local-only exec for now.
    shutil.rmtree(client.FOLDER, ignore_errors=True)
