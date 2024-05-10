|version| |python| |license| |ci| |coverage|

.. |version| image:: https://img.shields.io/pypi/v/paramiko
    :target: https://pypi.org/project/paramiko/
    :alt: PyPI - Package Version
.. |python| image:: https://img.shields.io/pypi/pyversions/paramiko
    :target: https://pypi.org/project/paramiko/
    :alt: PyPI - Python Version
.. |license| image:: https://img.shields.io/pypi/l/paramiko
    :target: https://github.com/paramiko/paramiko/blob/main/LICENSE
    :alt: PyPI - License
.. |ci| image:: https://img.shields.io/circleci/build/github/paramiko/paramiko/main
    :target: https://app.circleci.com/pipelines/github/paramiko/paramiko
    :alt: CircleCI
.. |coverage| image:: https://img.shields.io/codecov/c/gh/paramiko/paramiko
    :target: https://app.codecov.io/gh/paramiko/paramiko
    :alt: Codecov

Welcome to Paramiko!
====================

Paramiko is a pure-Python [#]_ (3.6+) implementation of the SSHv2 protocol
[#]_, providing both client and server functionality. It provides the
foundation for the high-level SSH library `Fabric <https://fabfile.org>`_,
which is what we recommend you use for common client use-cases such as running
remote shell commands or transferring files.

Direct use of Paramiko itself is only intended for users who need
advanced/low-level primitives or want to run an in-Python sshd.

For installation information, changelogs, FAQs and similar, please visit `our
main project website <https://paramiko.org>`_; for API details, see `the
versioned docs <https://docs.paramiko.org>`_. Additionally, the project
maintainer keeps a `roadmap <http://bitprophet.org/projects#roadmap>`_ on his
personal site.

.. [#]
    Paramiko relies on `cryptography <https://cryptography.io>`_ for crypto
    functionality, which makes use of C and Rust extensions but has many
    precompiled options available. See `our installation page
    <https://www.paramiko.org/installing.html>`_ for details.

.. [#]
    OpenSSH's RFC specification page is a fantastic resource and collection of
    links that we won't bother replicating here:
    https://www.openssh.com/specs.html

    OpenSSH itself also happens to be our primary reference implementation:
    when in doubt, we consult how they do things, unless there are good reasons
    not to. There are always some gaps, but we do our best to reconcile them
    when possible.
