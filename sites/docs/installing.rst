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

Cryptography provides statically built "wheels" for most common systems,
which modern "pip" will preferentially install. These include all needed
non-python components pre-built and should "just work".

If you need or want to build cryptography from source, you will need a
C build toolchain, development headers for Python, OpenSSL and
``libffi``, and starting with cryptography-3.4, also a Rust language
toolchain installed. Again, see `Cryptography's install docs`_;
these requirements may occasionally change.

- Cryptography-3.4 dropped support for Python-2.7
- Cryptography-3.3 dropped support for Python-3.5
- Cryptography-3.2 dropped support for OpenSSL-1.0.2

If you have a problem with these changing requirements, you can install
the last patch release before the incompatible minor release like::

    $ pip install 'cryptography<3.4'

.. _installation instructions:
.. _Cryptography's install docs: https://cryptography.io/en/latest/installation.html


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
