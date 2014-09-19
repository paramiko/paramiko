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

We currently support **Python 2.6, 2.7, 3.3+, and PyPy** (Python **3.2** should
also work but has a less-strong compatibility guarantee from us.) Users on
Python 2.5 or older are urged to upgrade.

Paramiko has two hard dependencies: the pure-Python ECDSA module ``ecdsa``, and
the Cryptography library. ``ecdsa`` is easily installable from wherever you
obtained Paramiko's package; Cryptography may require more work. Read on for
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


Cryptography
============

`Cryptography <https://cryptography.io>`_  provides the low-level (C-based)
encryption algorithms we need to implement the SSH protocol. There are a few
things to be aware of when installing Cryptography, because it includes a
C-extension.

C extension
-----------

Unless you are installing from a precompiled source such as a Debian apt
repository or RedHat RPM,, you will also need the ability to build Python
C-based modules from source in order to install Cryptography. Users on **Unix-
based platforms** such as Ubuntu or Mac OS X will need the traditional C build
toolchain installed (e.g. Developer Tools / XCode Tools on the Mac, or the
``build-essential`` package on Ubuntu or Debian Linux -- basically, anything
with ``gcc``, ``make`` and so forth) as well as the Python development
libraries, often named ``python-dev`` or similar, OpenSSL headers, often named
``libssl-dev``, and libffi development libraries, often named ``libffi-dev``.

For **Windows** users we recommend using the most recent version of ``pip``,
Cryptography has binary wheels on PyPI, which remove the need for having a C
compiler.


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
