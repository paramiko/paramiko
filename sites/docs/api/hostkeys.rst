Host keys / ``known_hosts`` files
=================================

``HostKeys`` loads OpenSSH marker lines ``@cert-authority`` (trust anchor for
host certificates matching the listed host patterns) and ``@revoked`` (keys
that must not be accepted). ``SSHClient`` consults these entries when
verifying the server host key, including certificate-based trust.

.. automodule:: paramiko.hostkeys
    :member-order: bysource
