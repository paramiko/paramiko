
========
paramiko
========

:Paramiko: Python SSH module
:Copyright: Copyright (c) 2003-2009  Robey Pointer <robeypointer@gmail.com>
:License: LGPL
:Homepage: http://www.lag.net/paramiko/


paramiko 1.7.6
==============

"Fanny" release, 1 november 2009


What
----

"paramiko" is a combination of the esperanto words for "paranoid" and
"friend".  it's a module for python 2.2+ that implements the SSH2 protocol
for secure (encrypted and authenticated) connections to remote machines.
unlike SSL (aka TLS), SSH2 protocol does not require heirarchical
certificates signed by a powerful central authority. you may know SSH2 as
the protocol that replaced telnet and rsh for secure access to remote
shells, but the protocol also includes the ability to open arbitrary
channels to remote services across the encrypted tunnel (this is how sftp
works, for example).

it is written entirely in python (no C or platform-dependent code) and is
released under the GNU LGPL (lesser GPL). 

the package and its API is fairly well documented in the "doc/" folder
that should have come with this archive.


Requirements
------------

  - python 2.3	<http://www.python.org/>
    (python 2.2 is also supported, but not recommended)
  - pycrypto 1.9+	<http://www.amk.ca/python/code/crypto.html>
    (2.0 works too)

pycrypto compiled for Win32 can be downloaded from the HashTar homepage:
    http://nitace.bsd.uchicago.edu:8080/hashtar

you can also build it yourself using the free MinGW tools and this command
line (thanks to Roger Binns for the info)::

    python setup.py build --compiler=mingw32 bdist_wininst

If you have setuptools, you can build and install paramiko and all its
dependencies with this command (as root)::

    easy_install ./


Portability
-----------

i code and test this library on Linux and MacOS X.  for that reason, i'm
pretty sure that it works for all posix platforms, including MacOS.  it
should also work on Windows, though i don't test it as frequently there.
if you run into Windows problems, send me a patch: portability is important
to me.

python 2.2 may work, thanks to some patches from Roger Binns.  things to
watch out for:

    * sockets in 2.2 don't support timeouts, so the 'select' module is
      imported to do polling.  
    * logging is mostly stubbed out.  it works just enough to let paramiko
      create log files for debugging, if you want them.  to get real logging,
      you can backport python 2.3's logging package.  Roger has done that
      already:
      http://sourceforge.net/project/showfiles.php?group_id=75211&package_id=113804

you really should upgrade to python 2.3.  laziness is no excuse! :)

some python distributions don't include the utf-8 string encodings, for
reasons of space (misdirected as that is).  if your distribution is
missing encodings, you'll see an error like this::

    LookupError: no codec search functions registered: can't find encoding

this means you need to copy string encodings over from a working system.
(it probably only happens on embedded systems, not normal python
installs.)  Valeriy Pogrebitskiy says the best place to look is
``.../lib/python*/encodings/__init__.py``.


Bugs & Support
--------------

there's a launchpage page for paramiko, with a bug tracker:

    https://launchpad.net/paramiko/
    
this is the primary place to file and browse bug reports.

there's also a low-traffic mailing list for support and discussions:

    http://www.lag.net/mailman/listinfo/paramiko


Demo
----

several demo scripts come with paramiko to demonstrate how to use it.
probably the simplest demo of all is this::

    import paramiko, base64
    key = paramiko.RSAKey(data=base64.decodestring('AAA...'))
    client = paramiko.SSHClient()
    client.get_host_keys().add('ssh.example.com', 'ssh-rsa', key)
    client.connect('ssh.example.com', username='strongbad', password='thecheat')
    stdin, stdout, stderr = client.exec_command('ls')
    for line in stdout:
        print '... ' + line.strip('\n')
    client.close()

...which prints out the results of executing ``ls`` on a remote server.
(the host key 'AAA...' should of course be replaced by the actual base64
encoding of the host key.  if you skip host key verification, the
connection is not secure!)

the following example scripts (in demos/) get progressively more detailed:

:demo_simple.py:
    calls invoke_shell() and emulates a terminal/tty through which you can
    execute commands interactively on a remote server.  think of it as a
    poor man's ssh command-line client.

:demo.py:
    same as demo_simple.py, but allows you to authenticiate using a
    private key, attempts to use an SSH-agent if present, and uses the long
    form of some of the API calls.

:forward.py:
    command-line script to set up port-forwarding across an ssh transport.
    (requires python 2.3.)

:demo_sftp.py:
    opens an sftp session and does a few simple file operations.

:demo_server.py:
    an ssh server that listens on port 2200 and accepts a login for
    'robey' (password 'foo'), and pretends to be a BBS.  meant to be a
    very simple demo of writing an ssh server.


Use
---

the demo scripts are probably the best example of how to use this package.
there is also a lot of documentation, generated with epydoc, in the doc/
folder.  point your browser there.  seriously, do it.  mad props to
epydoc, which actually motivated me to write more documentation than i
ever would have before.

there are also unit tests here::

    $ python ./test.py

which will verify that most of the core components are working correctly.
