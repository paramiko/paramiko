==========
Installing
==========

Paramiko-NG itself
==================

The recommended way to get Paramiko is to **install the latest stable release**
via `pip <http://pip-installer.org>`_::

    $ pip install paramiko-ng

You can also install under the original "paramiko" pip-package-name,
in order to satisfy requirements for other packages (replace "2.7.6" with desired version)::

    $ PARAMIKO_REPLACE=1 pip install https://github.com/ploxiln/paramiko-ng/archive/2.7.6.tar.gz#egg=paramiko

Paramiko-NG currently supports Python 2.7, 3.4+, and PyPy.

Paramiko-NG has only a few direct dependencies:

- The big one is Cryptography; see :ref:`its specific note below <cryptography>` for more details.
- `bcrypt <https://pypi.org/project/bcrypt/>`_, for "new openssh format" private keys
- `pynacl <https://pypi.org/project/PyNaCl/>`_, *optional* for Ed25519 key support

If you need GSS-API / SSPI support, see :ref:`the below subsection on it
<gssapi>` for details on its optional dependencies.


.. _cryptography:

Cryptography
============

`Cryptography <https://cryptography.io>`__  provides the low-level (C-based)
encryption algorithms we need to implement the SSH protocol. It has detailed
`installation instructions`_ (and an `FAQ <https://cryptography.io/en/latest/faq/>`_)
which you should read carefully.

In general, you'll need one of the following setups:

* On Windows or Mac OS X, provided your ``pip`` is modern (8.x+): nothing else
  is required. ``pip`` will install statically compiled binary archives of
  Cryptography & its dependencies.
* On Linux, or on other platforms with older versions of ``pip``: you'll need a
  C build toolchain, plus development headers for Python, OpenSSL and
  ``libffi``. Again, see `Cryptography's install docs`_; these requirements may
  occasionally change.

.. _installation instructions:
.. _Cryptography's install docs: https://cryptography.io/en/latest/installation/


.. _gssapi:

Optional dependencies for GSS-API / SSPI / Kerberos
===================================================

In order to use GSS-API/Kerberos & related functionality, a couple of
additional dependencies are required (these are not listed in our ``setup.py``
due to their infrequent utility & non-platform-agnostic requirements):

* All platforms need **a working installation of GSS-API itself**, e.g. Heimdal.
* All platforms need `pyasn1 <https://pypi.org/project/pyasn1/>`__ ``0.1.7`` or later.
* **Unix** needs `gssapi <https://pypi.org/project/gssapi/>`__ ``1.4.1`` or later.
* **Windows** needs `pywin32 <https://pypi.python.org/pypi/pywin32>`__ ``2.1.8`` or later.

.. note::
    If you use Microsoft SSPI for kerberos authentication and credential
    delegation, make sure that the target host is trusted for delegation in the
    active directory configuration. For details see:
    http://technet.microsoft.com/en-us/library/cc738491%28v=ws.10%29.aspx
