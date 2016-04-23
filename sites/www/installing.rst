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

We currently support **Python 2.6, 2.7, 3.3+, and PyPy**. Users on Python 2.5
or older (or 3.2 or older) are urged to upgrade.

Paramiko has only one direct hard dependency: the Cryptography library. See
:ref:`cryptography`.

If you need GSS-API / SSPI support, see :ref:`the below subsection on it
<gssapi>` for details on its optional dependencies.


.. _release-lines:

Release lines
-------------

Users desiring stability may wish to pin themselves to a specific release line
once they first start using Paramiko; to assist in this, we guarantee bugfixes
for the last 2-3 releases including the latest stable one.

This typically spans major & minor versions, so even if e.g. 3.1 is the latest
stable release, it's likely that bugfixes will occasionally come out for the
latest 2.x and perhaps even 1.x releases, as well as for 3.0.

If you're unsure which version to install, we have suggestions:

* **Completely new users** should always default to the **latest stable
  release** (as above, whatever is newest / whatever shows up with ``pip
  install paramiko``.)
* **Users upgrading from a much older version** (e.g. the 1.7.x line) should
  probably get the **oldest actively supported line** (check the
  :ref:`changelog` for recent releases).
* **Everybody else** is hopefully already "on" a given version and can
  carefully upgrade to whichever version they care to, when their release line
  stops being supported.


.. _cryptography:

Cryptography
============

`Cryptography <https://cryptography.io>`_  provides the low-level (C-based)
encryption algorithms we need to implement the SSH protocol. It has detailed
`installation instructions <crypto-install>`_ (and an `FAQ
<https://cryptography.io/en/latest/faq/>`_) which you should read carefully.

In general, you'll need one of the following setups:

* On Windows or Mac OS X, provided your ``pip`` is modern (8.x+): nothing else
  is required. ``pip`` will install statically compiled binary archives of
  Cryptography & its dependencies.
* On Linux, or on other platforms with older versions of ``pip``: you'll need a
  C build toolchain, plus development headers for Python, OpenSSL and CFFI.
  Again, see `Cryptography's install docs <crypto-install>`_; these
  requirements may occasionally change.

.. _crypto-install: https://cryptography.io/en/latest/installation/


.. _gssapi:

Optional dependencies for GSS-API / SSPI / Kerberos
===================================================

In order to use GSS-API/Kerberos & related functionality, a couple of
additional dependencies are required (these are not listed in our ``setup.py``
due to their infrequent utility & non-platform-agnostic requirements):

* It hopefully goes without saying but **all platforms** need **a working
  installation of GSS-API itself**, e.g. Heimdal.
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
