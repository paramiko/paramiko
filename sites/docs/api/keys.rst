============
Key handling
============

.. warning::
   Paramiko continues to support loading private key material from PEM-encoded
   files, but this is no longer considered good security practice, especially
   as the methodology required to decrypt such files involves MD5. Please
   consider switching to the OpenSSH format, which Paramiko is now able to both
   read and write for most key types.


Parent key class
================

.. automodule:: paramiko.pkey

RSA
===

.. automodule:: paramiko.rsakey

ECDSA
=====

.. automodule:: paramiko.ecdsakey

Ed25519
=======

.. automodule:: paramiko.ed25519key
