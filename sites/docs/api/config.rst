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
Paramiko directly supports (most of which involve the parsing/matching process
itself). It includes any departures from OpenSSH's implementation, which are
intentionally very few, and usually to support backwards compatibility with
Paramiko versions lacking some default parse-related behavior.

See `OpenSSH's own ssh_config docs <ssh_config>`_ for details on the overall
file format, and the intended meaning of the keywords and values; or check the
documentation for your Paramiko-using library of choice (again, often
`Fabric`_) to see what it honors on its end.

- ``AddressFamily``: used when looking up the local hostname for purposes of
  expanding the ``%l``/``%L`` :ref:`tokens <TOKENS>`.

  .. note::
    As with the rest of these keywords, it does **not** apply to actual SSH
    connections (as Paramiko's client classes do not load configs for you).

    In fact, OpenSSH itself does not use this setting the way Paramiko does
    (its lookup for ``%l`` does not appear to honor ``AddressFamily``).

- ``Host``: exact matching, full and partial globbing (``*``), negation
  (``!``), multiple (whitespace-delimited) patterns per keyword.
- ``HostName``: supplies potential values for ``%h`` :ref:`token expansions
  <TOKENS>`.
- ``IdentityFile``: its ability to be specified multiple times and result in a
  list of values is preserved in our parser. Values for this keyword will
  always be a list of strings, if present.
- ``LocalForward``: like ``IdentityFile``, results in a list of strings.
- ``Port``: supplies potential values for ``%p`` :ref:`token expansions
  <TOKENS>`.
- ``ProxyCommand``: see our `.ProxyCommand` class for an easy
  way to honor this keyword from a config you've parsed.

    - Supports :ref:`expansion tokens <TOKENS>`.
    - When a lookup would result in an effective ``ProxyCommand none``,
      Paramiko (as of 1.x-2.x) strips it from the resulting dict entirely. A
      later major version may retain the ``"none"`` marker for clarity's sake.

- ``RemoteForward``: like ``IdentityFile``, results in a list of strings.
- ``User``: supplies potential values for ``%u`` :ref:`token expansions
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
- ``%u``

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
