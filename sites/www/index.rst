Welcome to Paramiko!
====================

Paramiko is a Python (2.7, 3.4+) implementation of the SSHv2 protocol [#]_,
providing both client and server functionality. While it leverages a Python C
extension for low level cryptography (`Cryptography
<https://cryptography.io>`_), Paramiko itself is a pure Python interface around
SSH networking concepts.

This website covers project information for Paramiko such as the changelog,
contribution guidelines, development roadmap, news/blog, and so forth. Detailed
usage and API documentation can be found at our code documentation site,
`docs.paramiko.org <http://docs.paramiko.org>`_.

Please see the sidebar to the left to begin.

.. toctree::
    :hidden:

    changelog
    FAQs <faq>
    installing
    installing-1.x
    contributing
    contact


.. rubric:: Footnotes

.. [#]
    SSH is defined in :rfc:`4251`, :rfc:`4252`, :rfc:`4253` and :rfc:`4254`. The
    primary working implementation of the protocol is the `OpenSSH project
    <http://openssh.org>`_.  Paramiko implements a large portion of the SSH
    feature set, but there are occasional gaps.
