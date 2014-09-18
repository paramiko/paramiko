==========
Installing
==========

.. _paramiko-itself:

Paramiko itself
===============

The recommended way to get Paramiko is to **install the latest stable release**
via `pip <http://pip-installer.org>`_::

    $ pip install paramiko

.. note::
    Users who want the bleeding edge can install the development version via
    ``pip install paramiko==dev``.

We currently support **Python 2.6, 2.7 and 3.3+** (Python **3.2** should also
work but has a less-strong compatibility guarantee from us.) Users on Python
2.5 or older are urged to upgrade.

Paramiko has two hard dependencies: the pure-Python ECDSA module ``ecdsa``, and the
PyCrypto C extension. ``ecdsa`` is easily installable from wherever you
obtained Paramiko's package; PyCrypto may require more work. Read on for
details.

If you need GSS-API / SSPI support, see :ref:`the below subsection on it
<gssapi>` for details on additional dependencies.

.. _release-lines:

Release lines
-------------

Users desiring stability may wish to pin themselves to a specific release line
once they first start using Paramiko; to assist in this, we guarantee bugfixes
for the last 2-3 releases including the latest stable one.

If you're unsure which version to install, we have suggestions:

* **Completely new users** should always default to the **latest stable
  release** (as above, whatever is newest / whatever shows up with ``pip
  install paramiko``.)
* **Users upgrading from a much older version** (e.g. the 1.7.x line) should
  probably get the **oldest actively supported line** (see the paragraph above
  this list for what that currently is.)
* **Everybody else** is hopefully already "on" a given version and can
  carefully upgrade to whichever version they care to, when their release line
  stops being supported.


PyCrypto
========

`PyCrypto <https://www.dlitz.net/software/pycrypto/>`_  provides the low-level
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


.. _gssapi:

Optional dependencies for GSS-API / SSPI / Kerberos
===================================================

In order to use GSS-API/Kerberos & related functionality, a couple of
additional dependencies are required (these are not listed in our ``setup.py``
due to their infrequent utility & non-platform-agnostic requirements):

* It hopefully goes without saying but **all platforms** need **a working
  installation of GSS-API itself**, e.g. Heimdal.
* **All platforms** need `pyasn1 <https://pypi.python.org/pypi/pyasn1>`_
  ``0.1.7`` or better.
* **Unix** needs `python-gssapi <https://pypi.python.org/pypi/python-gssapi/>`_
  ``0.6.1`` or better.

  .. note:: This library appears to only function on Python 2.7 and up.

* **Windows** needs `pywin32 <https://pypi.python.org/pypi/pywin32>`_ ``2.1.8``
  or better.

.. note::
    If you use Microsoft SSPI for kerberos authentication and credential
    delegation, make sure that the target host is trusted for delegation in the
    active directory configuration. For details see:
    http://technet.microsoft.com/en-us/library/cc738491%28v=ws.10%29.aspx
