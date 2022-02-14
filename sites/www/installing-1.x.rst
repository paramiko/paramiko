================
Installing (1.x)
================

.. note:: Installing Paramiko 2.0 or above? See :doc:`installing` instead.

This document includes legacy notes on installing Paramiko 1.x (specifically,
1.13 and up). Users are strongly encouraged to upgrade to 2.0 when possible;
PyCrypto (the dependency covered below) is no longer maintained and contains
security vulnerabilities.

General install notes
=====================

* Python 2.6+ and 3.3+ are supported; Python <=2.5 and 3.0-3.2 are **not
  supported**.
* See the note in the main install doc about :ref:`release-lines` for details
  on specific versions you may want to install.
  
  .. note:: 1.x will eventually be entirely end-of-lifed.
* Paramiko 1.7-1.14 have only one dependency: :ref:`pycrypto`.
* Paramiko 1.15+ (not including 2.x and above) add a second, pure-Python
  dependency: the ``ecdsa`` module, trivially installable via PyPI.
* Paramiko 1.15+ (again, not including 2.x and up) also allows you to
  optionally install a few more dependencies to gain support for
  :ref:`GSS-API/Kerberos <gssapi-on-1x>`.
* Users on Windows may want to opt for the :ref:`pypm` approach.


.. _pycrypto:

PyCrypto
========

`PyCrypto <https://www.dlitz.net/software/pycrypto/>`__  provides the low-level
(C-based) encryption algorithms we need to implement the SSH protocol. There
are a couple gotchas associated with installing PyCrypto: its compatibility
with Python's package tools, and the fact that it is a C-based extension.

C extension
-----------

Unless you are installing from a precompiled source such as a Debian apt
repository or RedHat RPM, or using :ref:`pypm <pypm>`, you will also need the
ability to build Python C-based modules from source in order to install
PyCrypto. Users on **Unix-based platforms** such as Ubuntu or Mac OS X will
need the traditional C build toolchain installed (e.g. Developer Tools / XCode
Tools on the Mac, or the ``build-essential`` package on Ubuntu or Debian Linux
-- basically, anything with ``gcc``, ``make`` and so forth) as well as the
Python development libraries, often named ``python-dev`` or similar.

Slow vs fast crypto math
~~~~~~~~~~~~~~~~~~~~~~~~

PyCrypto attempts to use the ``gmp`` C math library if it is present on your
system, which enables what it internally calls "fastmath" (``_fastmath.so``).
When those headers are not available, it falls back to "slowmath"
(``_slowmath.py``) which is a pure-Python implementation.

Real-world tests have shown significant benefits to using the C version of this
code; thus we strongly recommend you install the ``gmp`` development headers
**before** installing Paramiko/PyCrypto. E.g.::

    $ apt-get install libgmp-dev # or just apt
    $ yum install gmp-devel # or dnf
    $ brew install gmp

If you're unsure which version of math you've ended up with, a quick way to
check is to examine whether ``_fastmath.so`` or ``_slowmath.py`` appears in the
output of::

    from Crypto.PublicKey import RSA
    print(RSA._impl._math)

Windows
~~~~~~~

For **Windows** users we recommend using :ref:`pypm`, installing a C
development environment such as `Cygwin <http://cygwin.com>`_ or obtaining a
precompiled Win32 PyCrypto package from `voidspace's Python modules page
<http://www.voidspace.org.uk/python/modules.shtml#pycrypto>`_.

.. note::
    Some Windows users whose Python is 64-bit have found that the PyCrypto
    dependency ``winrandom`` may not install properly, leading to ImportErrors.
    In this scenario, you'll probably need to compile ``winrandom`` yourself
    via e.g. MS Visual Studio.  See `Fabric #194
    <https://github.com/fabric/fabric/issues/194>`_ for info.


.. _pypm:

ActivePython and PyPM
=====================

Windows users who already have ActiveState's `ActivePython
<http://www.activestate.com/activepython/downloads>`_ distribution installed
may find Paramiko is best installed with `its package manager, PyPM
<http://code.activestate.com/pypm/>`_. Below is example output from an
installation of Paramiko via ``pypm``::

    C:\> pypm install paramiko
    The following packages will be installed into "%APPDATA%\Python" (2.7):
     paramiko-1.7.8 pycrypto-2.4
    Get: [pypm-free.activestate.com] paramiko 1.7.8
    Get: [pypm-free.activestate.com] pycrypto 2.4
    Installing paramiko-1.7.8
    Installing pycrypto-2.4
    C:\>


.. _gssapi-on-1x:

Optional dependencies for GSS-API / SSPI / Kerberos
===================================================

First, see the main install doc's notes: :ref:`gssapi` - everything there is
required for Paramiko 1.x as well.

Additionally, users of Paramiko 1.x, on all platforms, need a final dependency:
`pyasn1 <https://pypi.org/project/pyasn1/>`_ ``0.1.7`` or better.
