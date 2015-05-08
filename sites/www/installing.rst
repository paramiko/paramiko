==========
Installing
==========

Paramiko itself
===============

The recommended way to get Paramiko is to **install the latest stable release**
via `pip <http://pip-installer.org>`_::

    $ pip install paramiko

.. note::
    Users who want the bleeding edge can install the development version via
    ``pip install paramiko==dev``.

We currently support **Python 2.5/2.6/2.7**, with support for Python 3 coming
soon. Users on Python 2.4 or older are urged to upgrade. Paramiko *may* work on
Python 2.4 still, but there is no longer any support guarantee.

Paramiko has two dependencies: the pure-Python ECDSA module ``ecdsa``, and the
PyCrypto C extension. ``ecdsa`` is easily installable from wherever you
obtained Paramiko's package; PyCrypto may require more work. Read on for
details.

PyCrypto
========

`PyCrypto <https://www.dlitz.net/software/pycrypto/>`_  provides the low-level
(C-based) encryption algorithms we need to implement the SSH protocol. There
are a couple gotchas associated with installing PyCrypto: its compatibility
with Python's package tools, and the fact that it is a C-based extension.

.. _pycrypto-and-pip:

Possible gotcha on older Python and/or pip versions
---------------------------------------------------

We strongly recommend using ``pip`` to as it is newer and generally better than
``easy_install``. However, a combination of bugs in specific (now rather old)
versions of Python, ``pip`` and PyCrypto can prevent installation of PyCrypto.
Specifically:

* Python = 2.5.x
* PyCrypto >= 2.1 (required for most modern versions of Paramiko)
* ``pip`` < 0.8.1

When all three criteria are met, you may encounter ``No such file or
directory`` IOErrors when trying to ``pip install paramiko`` or ``pip install
PyCrypto``.

The fix is to make sure at least one of the above criteria is not met, by doing
the following (in order of preference):

* Upgrade to ``pip`` 0.8.1 or above, e.g. by running ``pip install -U pip``.
* Upgrade to Python 2.6 or above.
* Downgrade to Paramiko 1.7.6 or 1.7.7, which do not require PyCrypto >= 2.1,
  and install PyCrypto 2.0.1 (the oldest version on PyPI which works with
  Paramiko 1.7.6/1.7.7)


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
