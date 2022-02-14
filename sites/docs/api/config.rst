=============
Configuration
=============

Paramiko **does not itself** leverage `OpenSSH-style config file directives
<ssh_config>`_, but it **does** implement a parser for the format, which users
can honor themselves (and is used by higher-level libraries, such as
`Fabric`_).

The API for this is `.SSHConfig`, which loads SSH config files from disk,
file-like object, or string and exposes a "look up a hostname, get a dict of
applicable keywords/values back" functionality.

As with OpenSSH's own support, this dict will contain values from across the
parsed file, depending on the order in which keywords were encountered and how
specific or generic the ``Host`` or ``Match`` directives were.

.. note:;
    Result keys are lowercased for consistency and ease of deduping, as the
    overall parsing/matching is itself case-insensitive. Thus, a source file
    containing e.g. ``ProxyCommand`` will result in lookup results like
    ``{"proxycommand": "shell command here"}``.


.. _ssh-config-support:

Keywords currently supported
============================

The following is an alphabetical list of which `ssh_config`_ directives
Paramiko interprets during the parse/lookup process (as above, actual SSH
connections **do not** reference parsed configs). Departures from `OpenSSH's
implementation <ssh_config>`_ (e.g. to support backwards compat with older
Paramiko releases) are included. A keyword by itself means no known departures.

- ``AddressFamily``: used when looking up the local hostname for purposes of
  expanding the ``%l``/``%L`` :ref:`tokens <TOKENS>` (this is actually a minor
  value-add on top of OpenSSH, which doesn't actually honor this setting when
  expanding ``%l``).
- ``CanonicalDomains``

    .. versionadded:: 2.7

- ``CanonicalizeFallbackLocal``: when ``no``, triggers raising of
  `.CouldNotCanonicalize` for target hostnames which do not successfully
  canonicalize.

    .. versionadded:: 2.7

- ``CanonicalizeHostname``: along with the other ``Canonicaliz*`` settings
  (sans ``CanonicalizePermittedCNAMEs``, which is not yet implemented), enables
  hostname canonicalization, insofar as calling `.SSHConfig.lookup` with a
  given hostname will return a canonicalized copy of the config data, including
  an updated ``HostName`` value.

    .. versionadded:: 2.7

- ``CanonicalizeMaxDots``

    .. versionadded:: 2.7

- ``Host``
- ``HostName``: used in ``%h`` :ref:`token expansion <TOKENS>`
- ``Match``: fully supported, with the following caveats:

    - You must have the optional dependency Invoke installed; see :ref:`the
      installation docs <paramiko-itself>` (in brief: install
      ``paramiko[invoke]`` or ``paramiko[all]``).
    - As usual, connection-time information is not present during config
      lookup, and thus cannot be used to determine matching. This primarily
      impacts ``Match user``, which can match against loaded ``User`` values
      but has no knowledge about connection-time usernames.

    .. versionadded:: 2.7

- ``Port``: supplies potential values for ``%p`` :ref:`token expansion
  <TOKENS>`.
- ``ProxyCommand``: see our `.ProxyCommand` class for an easy
  way to honor this keyword from a config you've parsed.

    - Honors :ref:`token expansion <TOKENS>`.
    - When a lookup would result in an effective ``ProxyCommand none``,
      Paramiko (as of 1.x-2.x) strips it from the resulting dict entirely. A
      later major version may retain the ``"none"`` marker for clarity's sake.

- ``User``: supplies potential values for ``%u`` :ref:`token expansion
  <TOKENS>`.

.. _TOKENS:

Expansion tokens
----------------

We support most SSH config expansion tokens where possible, so when they are
present in a config file source, the result of a `.SSHConfig.lookup` will
contain the expansions/substitutions (based on the rest of the config or
properties of the local system).

Specifically, we are known to support the below, where applicable (e.g. as in
OpenSSH, ``%L`` works in ``ControlPath`` but not elsewhere):

- ``%d``
- ``%h``
- ``%l``
- ``%L``
- ``%n``
- ``%p``
- ``%r``
- ``%u``: substitutes the configured ``User`` value, or the local user (as seen
  by ``getpass.getuser``) if not specified.

In addition, we extend OpenSSH's tokens as follows:

- ``~`` is treated like ``%d`` (expands to the local user's home directory
  path) when expanding ``ProxyCommand`` values, since ``ProxyCommand`` does not
  natively support ``%d`` for some reason.


.. _ssh_config: https://man.openbsd.org/ssh_config
.. _Fabric: http://fabfile.org


``config`` module API documentation
===================================

Mostly of interest to contributors; see previous section for behavioral
details.

.. automodule:: paramiko.config
    :member-order: bysource
