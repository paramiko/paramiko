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

Paramiko is a pure-Python [#]_ (2.7, 3.4+) implementation of the SSHv2 protocol
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
    SSH is defined in :rfc-reference:`4251`, :rfc-reference:`4252`,
    :rfc-reference:`4253` and :rfc-reference:`4254`. The primary working
    implementation of the protocol is the `OpenSSH project
    <http://openssh.org>`_.  Paramiko implements a large portion of the SSH
    feature set, but there are occasional gaps.
