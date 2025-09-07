==========
Installing
==========


.. note::
    These instructions cover Paramiko 2.0 and above. If you're looking to
    install Paramiko 1.x, see :doc:`installing-1.x`. However, **the 1.x line
    relies on insecure dependencies** so upgrading is strongly encouraged.


.. _paramiko-itself:

Paramiko itself
===============

The recommended way to get Paramiko is to **install the latest stable release**
via `pip <http://pip-installer.org>`_::

    $ pip install paramiko

Paramiko has only a few **direct dependencies**:

- The big one, with its own sub-dependencies, is Cryptography; see :ref:`its
  specific note below <cryptography>` for more details;
- `bcrypt <https://pypi.org/project/bcrypt/>`_ and `pynacl
  <https://pypi.org/project/PyNaCl/>`_ for Ed25519 key support.

There are also a handful of **optional dependencies** you may install using
`setuptools 'extras'
<https://packaging.python.org/tutorials/installing-packages/#installing-setuptools-extras>`_:

- For GSS-API / SSPI support, use ``paramiko[gssapi]``, though also see
  :ref:`the below subsection on it <gssapi>` for details.


.. _release-lines:

Release lines
-------------

Users desiring stability may wish to pin themselves to a specific release line
once they first start using Paramiko; to assist in this, we guarantee bugfixes
for the last 2-3 releases including the latest stable one.

This typically spans major & minor versions, so even if e.g. 3.1 is the latest
stable release, it's likely that bugfixes will occasionally come out for the
latest 2.x and perhaps even 1.x releases, as well as for 3.0. New feature
releases for previous major-version lines are less likely but not unheard of.

If you're unsure which version to install:

* **Completely new users** should always default to the **latest stable
  release** (as above, whatever is newest / whatever shows up with ``pip
  install paramiko``.)
* **Users upgrading from a much older version** (e.g. 1.7.x through 1.10.x)
  should probably get the **oldest actively supported line** (check the
  :doc:`changelog` for recent releases).
* **Everybody else** is hopefully already "on" a given version and can
  carefully upgrade to whichever version they care to, when their release line
  stops being supported.


.. _cryptography:

Cryptography
============

`Cryptography <https://cryptography.io>`__  provides the low-level (C-based)
encryption algorithms we need to implement the SSH protocol. It has detailed
`installation instructions`_ (and an `FAQ
<https://cryptography.io/en/latest/faq/>`_) which you should read carefully.

In general, you'll need one of the following setups:

* On Windows or Mac OS X, provided your ``pip`` is modern (8.x+): nothing else
  is required. ``pip`` will install statically compiled binary archives of
  Cryptography & its dependencies.
* On Linux, or on other platforms with older versions of ``pip``: you'll need a
  C build toolchain, plus development headers for Python, OpenSSL and
  ``libffi``. Again, see `Cryptography's install docs`_; these requirements may
  occasionally change.

  .. warning::
    If you go this route, note that **OpenSSL 1.0.1 or newer is effectively
    required**. Cryptography 1.3 and older technically allow OpenSSL 0.9.8, but
    1.4 and newer - which Paramiko will gladly install or upgrade, if you e.g.
    ``pip install -U`` - drop that support.

* Similarly, Cryptography 3.4 and above require Rust language tooling to
  install from source; once again see Cryptography's documentation for details
  here, such as `their Rust install section`_ and `this FAQ entry`_.

.. _installation instructions:
.. _Cryptography's install docs: https://cryptography.io/en/latest/installation.html
.. _their Rust install section: https://cryptography.io/en/latest/installation.html#rust
.. _this FAQ entry: https://cryptography.io/en/latest/faq.html#installing-cryptography-fails-with-error-can-not-find-rust-compiler


.. _gssapi:

Optional dependencies for GSS-API / SSPI / Kerberos
===================================================

In order to use GSS-API/Kerberos & related functionality, additional
dependencies are required. It hopefully goes without saying but **all
platforms** need **a working installation of GSS-API itself**, e.g. Heimdal.

.. note::
    If you use Microsoft SSPI for kerberos authentication and credential
    delegation, make sure that the target host is trusted for delegation in the
    active directory configuration. For details see:
    http://technet.microsoft.com/en-us/library/cc738491%28v=ws.10%29.aspx

The ``gssapi`` "extra" install flavor
-------------------------------------

If you're installing via ``pip`` (recommended), you should be able to get the
optional Python package requirements by changing your installation to refer to
``paramiko[gssapi]`` (from simply ``paramiko``), e.g.::

    pip install "paramiko[gssapi]"

(Or update your ``requirements.txt``, or etc.)


.. TODO: just axe this once legacy gssapi support is gone, no point reiterating

Manual dependency installation
------------------------------

If you're not using ``pip`` or your ``pip`` is too old to support the "extras"
functionality, the optional dependencies are as follows:

* All platforms need `pyasn1 <https://pypi.org/project/pyasn1/>`_ ``0.1.7`` or
  later.
* **Unix** needs: `gssapi <https://pypi.org/project/gssapi/>`__ ``1.4.1`` or better.

    * An alternative is the `python-gssapi
      <https://pypi.org/project/python-gssapi/>`_ library (``0.6.1`` or above),
      though it is no longer maintained upstream, and Paramiko's support for
      its API may eventually become deprecated.

* **Windows** needs `pywin32 <https://pypi.python.org/pypi/pywin32>`_ ``2.1.8``
  or better.
