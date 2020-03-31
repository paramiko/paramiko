====================================
Welcome to Paramiko's documentation!
====================================

**Paramiko-NG** is a Python (2.7, 3.4+) implementation of the SSHv2 protocol [#]_,
providing both client and server functionality. While it leverages a Python C
extension for low level cryptography (`Cryptography <https://cryptography.io>`_),
Paramiko-NG itself is a pure Python interface around SSH networking concepts.

This site covers **Paramiko-NG**'s usage & API documentation. Paramiko-NG is still
usually referred to as Paramiko in the documentation, and it is still imported
as ``paramiko``.

For information about installing Paramiko-NG: :doc:`installing`

.. rubric:: Footnotes

.. [#]
    SSH is defined in :rfc:`4251`, :rfc:`4252`, :rfc:`4253` and :rfc:`4254`. The
    primary working implementation of the protocol is the `OpenSSH project
    <http://openssh.org>`_.  Paramiko implements a large portion of the SSH
    feature set, but there are occasional gaps.


API documentation
=================

The high-level client API starts with creation of an `.SSHClient` object. For
more direct control, pass a socket (or socket-like object) to a `.Transport`,
and use `start_server <.Transport.start_server>` or `start_client
<.Transport.start_client>` to negotiate with the remote host as either a server
or client.

As a client, you are responsible for authenticating using a password or private
key, and checking the server's host key. (Key signature and verification is
done by paramiko, but you will need to provide private keys and check that the
content of a public key matches what you expected to see.)

As a server, you are responsible for deciding which users, passwords, and keys
to allow, and what kind of channels to allow.

Once you have finished, either side may request flow-controlled `channels
<.Channel>` to the other side, which are Python objects that act like sockets,
but send and receive data over the encrypted session.

For details, please see the following tables of contents (which are organized
by area of interest.)


Core SSH protocol classes
-------------------------

.. toctree::
    api/channel
    api/client
    api/message
    api/packet
    api/transport


Authentication & keys
---------------------

.. toctree::
    api/agent
    api/hostkeys
    api/keys
    api/ssh_gss
    api/kex_gss


Other primary functions
-----------------------

.. toctree::
    api/config
    api/proxy
    api/server
    api/sftp


Miscellany
----------

.. toctree::
    api/buffered_pipe
    api/file
    api/pipe
    api/ssh_exception


Appendix
========

.. toctree::
    :maxdepth: 1

    installing
    faq
    old_changelog
