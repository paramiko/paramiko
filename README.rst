===========
Paramiko-NG
===========

This is a fork of `paramiko <https://github.com/paramiko/paramiko/>`_ for more active maintenance.

This is still imported under the name ``paramiko``, but you can
install with the package name *paramiko-ng* (default) or *paramiko*
(by setting the environment variable ``PARAMIKO_REPLACE``, see `Installation`_).

For changes in releases of this fork, see `releases <https://github.com/ploxiln/paramiko-ng/releases>`_

.. Continuous integration and code coverage badges

.. image:: https://travis-ci.org/ploxiln/paramiko-ng.svg?branch=master
    :target: https://travis-ci.org/ploxiln/paramiko-ng

:Paramiko-NG: Python SSH module
:Copyright:   Copyright (c) 2003-2009  Robey Pointer <robeypointer@gmail.com>
:Copyright:   Copyright (c) 2013-2018  Jeff Forcier <jeff@bitprophet.org>
:Copyright:   Copyright (c) 2019       Pierce Lopez <pierce.lopez@gmail.com>
:License:     `LGPL <https://www.gnu.org/copyleft/lesser.html>`_
:API docs:    http://docs.paramiko.org
:Development: https://github.com/ploxiln/paramiko-ng/


What
----

"Paramiko" is a combination of the Esperanto words for "paranoid" and
"friend".  It's a module for Python 2.7/3.4+ that implements the SSH2 protocol
for secure (encrypted and authenticated) connections to remote machines. Unlike
SSL (aka TLS), SSH2 protocol does not require hierarchical certificates signed
by a powerful central authority.  You may know SSH2 as the protocol that
replaced Telnet and rsh for secure access to remote shells, but the protocol
also includes the ability to open arbitrary channels to remote services across
the encrypted tunnel (this is how SFTP works, for example).

It is written entirely in Python (though it depends on third-party C wrappers
for low level crypto; these are often available precompiled) and is released
under the GNU Lesser General Public License (`LGPL <https://www.gnu.org/copyleft/lesser.html>`_).


Installation
------------

The import name is still just ``paramiko``. Make sure the original *paramiko*
is not installed before installing *paramiko-ng* - otherwise pip may report
success even though *paramiko-ng* was not correctly installed.

The most common way to install is simply::

    pip install paramiko-ng

To install the development version::

    pip install -e git+https://github.com/ploxiln/paramiko-ng/#egg=paramiko-ng

You can also install under the original "paramiko" pip-package-name,
in order to satisfy requirements for other packages::

    PARAMIKO_REPLACE=1 pip install https://github.com/ploxiln/paramiko-ng/archive/2.5.0.tar.gz#egg=paramiko

Replace "2.5.0" with the desired recent release, or for the latest development version do::

    PARAMIKO_REPLACE=1 pip install git+https://github.com/ploxiln/paramiko-ng/#egg=paramiko

The primary dependency is Cryptography, which has its own installation
`instructions <https://cryptography.io/en/latest/installation/>`_.


Portability Issues
------------------

Paramiko primarily supports POSIX platforms with standard OpenSSH
implementations, and is most frequently tested on Linux and OS X.  Windows is
supported as well, though it may not be as straightforward.


Bugs & Support
--------------

:Bug Reports:  `Github <https://github.com/ploxiln/paramiko-ng/issues/>`_
:IRC:          ``#paramiko`` on Freenode


Kerberos Support
----------------

Paramiko ships with optional Kerberos/GSSAPI support; for info on the extra
dependencies for this, see the `GSS-API section <http://www.paramiko.org/installing.html#gssapi>`_
on the main Paramiko website.


Demo
----

Several demo scripts come with Paramiko to demonstrate how to use it.
Probably the simplest demo is this::

    import base64
    import paramiko
    key = paramiko.RSAKey(data=base64.b64decode(b'AAA...'))
    client = paramiko.SSHClient()
    client.get_host_keys().add('ssh.example.com', 'ssh-rsa', key)
    client.connect('ssh.example.com', username='strongbad', password='thecheat')
    stdin, stdout, stderr = client.exec_command('ls')
    for line in stdout:
        print('... ' + line.strip('\n'))
    client.close()

This prints out the results of executing ``ls`` on a remote server. The host
key ``b'AAA...'`` should of course be replaced by the actual base64 encoding of the
host key.  If you skip host key verification, the connection is not secure!

The following example scripts (in demos/) get progressively more detailed:

:demo_simple.py:
    Calls invoke_shell() and emulates a terminal/TTY through which you can
    execute commands interactively on a remote server.  Think of it as a
    poor man's SSH command-line client.

:demo.py:
    Same as demo_simple.py, but allows you to authenticate using a private
    key, attempts to use an SSH agent if present, and uses the long form of
    some of the API calls.

:forward.py:
    Command-line script to set up port-forwarding across an SSH transport.

:demo_sftp.py:
    Opens an SFTP session and does a few simple file operations.

:demo_server.py:
    An SSH server that listens on port 2200 and accepts a login for
    'robey' (password 'foo'), and pretends to be a BBS.  Meant to be a
    very simple demo of writing an SSH server.

:demo_keygen.py:
    A key generator similar to OpenSSH ``ssh-keygen(1)`` program with
    Paramiko keys generation and progress functions.

Use
---

The demo scripts are probably the best example of how to use this package.

A much easier alternative to using paramiko directly is to use `Fabric <https://www.fabfile.org/>`_.
There is also `fab-classic <https://github.com/ploxiln/fab-classic/#readme>`_, a fork of Fabric-1.x
which works a bit differently. For either of these, currently, you need to install *paramiko-ng*
with the pip-package-name *paramiko*, using the ``PARAMIKO_REPLACE`` environment varariable
as described in `Installation`_.

There are also unit tests which will verify that most of the components are working correctly::

    $ pip install -r dev-requirements.txt
    $ pytest

