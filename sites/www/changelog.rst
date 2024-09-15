=========
Changelog
=========

- :release:`3.5.0 <2024-09-15>`
- :feature:`982` (via :issue:`2444`, which was a rebase of :issue:`2157`) Add
  support for AES-GCM encryption ciphers (128 and 256 bit variants). Thanks to
  Alex Gaynor for the report (& for cryptography review), Shen Cheng for the
  original PR, and Chris Mason for the updated PR; plus as usual to everyone
  who tested the patches and reported their results!

  This functionality has been tested in client mode against OpenSSH 9.0, 9.2,
  and 9.6, as well as against a number of proprietary appliance SSH servers.
- :bug:`-` Check for ``None`` transport members inside
  `~paramiko.channel.Channel` when closing the channel; this likely doesn't
  come up much in the real world, but was causing warnings in the test suite.
- :release:`3.4.1 <2024-08-11>`
- :release:`3.3.2 <2024-08-11>`
- :bug:`2419` (fixed in :issue:`2421`) Massage our import of the TripleDES
  cipher to support Cryptography >=43; this should prevent
  ``CryptographyDeprecationWarning`` from appearing upon import. Thanks to
  Erick Alejo for the report and Bryan Banda for the patch.
- :bug:`2420` Modify a test-harness skiptest check to work with newer versions
  of Cryptography. Props to Paul Howarth for the patch.
- :bug:`2353` Fix a 64-bit-ism in the test suite so the tests don't encounter a
  false negative on 32-bit systems. Reported by Stanislav Levin.
- :release:`3.4.0 <2023-12-18>`
- :feature:`-` `Transport` grew a new ``packetizer_class`` kwarg for overriding
  the packet-handler class used internally. Mostly for testing, but advanced
  users may find this useful when doing deep hacks.
- :bug:`- major` Address `CVE 2023-48795 <https://terrapin-attack.com/>`_ (aka
  the "Terrapin Attack", a vulnerability found in the SSH protocol re:
  treatment of packet sequence numbers) as follows:

    - The vulnerability only impacts encrypt-then-MAC digest algorithms in
      tandem with CBC ciphers, and ChaCha20-poly1305; of these, Paramiko
      currently only implements ``hmac-sha2-(256|512)-etm`` in tandem with
      ``AES-CBC``. If you are unable to upgrade to Paramiko versions containing
      the below fixes right away, you may instead use the
      ``disabled_algorithms`` connection option to disable the ETM MACs and/or
      the CBC ciphers (this option is present in Paramiko >=2.6).
    - As the fix for the vulnerability requires both ends of the connection to
      cooperate, the below changes will only take effect when the remote end is
      OpenSSH >= 9.6 (or equivalent, such as Paramiko in server mode, as of
      this patch version) and configured to use the new "strict kex" mode.
      Paramiko will always attempt to use "strict kex" mode if offered by the
      server, unless you override this by specifying ``strict_kex=False`` in
      `Transport.__init__`.
    - Paramiko will now raise an `SSHException` subclass (`MessageOrderError`)
      when protocol messages are received in unexpected order. This includes
      situations like receiving ``MSG_DEBUG`` or ``MSG_IGNORE`` during initial
      key exchange, which are no longer allowed during strict mode.
    - Key (re)negotiation -- i.e. ``MSG_NEWKEYS``, whenever it is encountered
      -- now resets packet sequence numbers. (This should be invisible to users
      during normal operation, only causing exceptions if the exploit is
      encountered, which will usually result in, again, `MessageOrderError`.)
    - Sequence number rollover will now raise `SSHException` if it occurs
      during initial key exchange (regardless of strict mode status).

  Thanks to Fabian Bäumer, Marcus Brinkmann, and Jörg Schwenk for submitting
  details on the CVE prior to release.

- :bug:`- major` Tweak ``ext-info-(c|s)`` detection during KEXINIT protocol
  phase; the original implementation made assumptions based on an OpenSSH
  implementation detail.
- :release:`3.3.1 <2023-07-28>`
- :bug:`-` Cleaned up some very old root level files, mostly just to exercise
  some of our doc build and release machinery. This changelog entry
  intentionally left blank! ``nothing-to-see-here-move-along.gif``
- :release:`3.3.0 <2023-07-28>`
- :feature:`1907` (solves :issue:`1992`) Add support and tests for ``Match
  final …`` (frequently used in ProxyJump configurations to exclude the jump
  host) to our :ref:`SSH config parser <ssh-config-support>`. Patch by
  ``@commonism``.
- :feature:`2058` (solves :issue:`1587` and possibly others) Add an explicit
  ``max_concurrent_prefetch_requests`` argument to
  `paramiko.client.SSHClient.get` and `paramiko.client.SSHClient.getfo`,
  allowing users to limit the number of concurrent requests used during
  prefetch. Patch by ``@kschoelhorn``, with a test by ``@bwinston-sdp``.
- :release:`3.2.0 <2023-05-25>`
- :bug:`- major` Fixed a very sneaky bug found at the apparently
  rarely-traveled intersection of ``RSA-SHA2`` keys, certificates, SSH agents,
  and stricter-than-OpenSSH server targets. This manifested as yet another
  "well, if we turn off SHA2 at one end or another, everything works again"
  problem, for example with version 12 of the Teleport server endpoint.

  This has been fixed; Paramiko tweaked multiple aspects of how it requests
  agent signatures, and the agent appears to do the right thing now.

  Thanks to Ryan Stoner for the bug report and testing.
- :bug:`2012 major` (also :issue:`1961` and countless others) The
  ``server-sig-algs`` and ``RSA-SHA2`` features added around Paramiko 2.9 or
  so, had the annoying side effect of not working with servers that don't
  support *either* of those feature sets, requiring use of
  ``disabled_algorithms`` to forcibly disable the SHA2 algorithms on Paramiko's
  end.

  The **experimental** `~paramiko.transport.ServiceRequestingTransport` (noted
  in its own entry in this changelog) includes a fix for this issue,
  specifically by falling back to the same algorithm as the in-use pubkey if
  it's in the algorithm list (leaving the "first algorithm in said list" as an
  absolute final fallback).
- :feature:`-` Implement ``_fields()`` on `~paramiko.agent.AgentKey` so that it
  may be compared (via ``==``) with other `~paramiko.pkey.PKey` instances.
- :bug:`23 major` Since its inception, Paramiko has (for reasons lost to time)
  implemented authentication as a side effect of handling affirmative replies
  to ``MSG_SERVICE_REQUEST`` protocol messages. What this means is Paramiko
  makes one such request before every ``MSG_USERAUTH_REQUEST``, i.e. every auth
  attempt.

  OpenSSH doesn't care if clients send multiple service requests, but other
  server implementations are often stricter in what they accept after an
  initial service request (due to the RFCs not being clear). This can result in
  odd behavior when a user doesn't authenticate successfully on the very first
  try (for example, when the right key for a target host is the third in one's
  ssh-agent).

  This version of Paramiko now contains an opt-in
  `~paramiko.transport.Transport` subclass,
  `~paramiko.transport.ServiceRequestingTransport`, which more-correctly
  implements service request handling in the Transport, and uses an
  auth-handler subclass internally which has been similarly adapted. Users
  wanting to try this new experimental code path may hand this class to
  `SSHClient.connect <paramiko.client.SSHClient.connect>` as its
  ``transport_factory`` kwarg.

  .. warning::
      This feature is **EXPERIMENTAL** and its code may be subject to change.

      In addition:
        - minor backwards incompatible changes exist in the new code paths,
          most notably the removal of the (inconsistently applied and rarely
          used) ``event`` arguments to the ``auth_xxx`` methods.
        - GSSAPI support has only been partially implemented, and is untested.

  .. note::
      Some minor backwards-*compatible* changes were made to the **existing**
      Transport and AuthHandler classes to facilitate the new code. For
      example, ``Transport._handler_table`` and
      ``AuthHandler._client_handler_table`` are now properties instead of raw
      attributes.

- :feature:`387` Users of `~paramiko.client.SSHClient` can now configure the
  authentication logic Paramiko uses when connecting to servers; this
  functionality is intended for advanced users and higher-level libraries such
  as `Fabric <https://fabfile.org>`_. See `~paramiko.auth_strategy` for
  details.

  Fabric's co-temporal release includes a proof-of-concept use of this feature,
  implementing an auth flow much closer to that of the OpenSSH client (versus
  Paramiko's legacy behavior). It is **strongly recommended** that if this
  interests you, investigate replacing any direct use of ``SSHClient`` with
  Fabric's ``Connection``.

  .. warning::
      This feature is **EXPERIMENTAL**; please see its docs for details.

- :feature:`-` Enhanced `~paramiko.agent.AgentKey` with new attributes, such
  as:

    - Added a ``comment`` attribute (and constructor argument);
      `Agent.get_keys() <paramiko.agent.Agent.get_keys>` now uses this kwarg to
      store any comment field sent over by the agent. The original version of
      the agent feature inexplicably did not store the comment anywhere.
    - Agent-derived keys now attempt to instantiate a copy of the appropriate
      key class for access to other algorithm-specific members (eg key size).
      This is available as the ``.inner_key`` attribute.

  .. note::
      This functionality is now in use in Fabric's new ``--list-agent-keys``
      feature, as well as in Paramiko's debug logging.

- :feature:`-` `~paramiko.pkey.PKey` now offers convenience
  "meta-constructors", static methods that simplify the process of
  instantiating the correct subclass for a given key input.

  For example, `PKey.from_path <paramiko.pkey.PKey.from_path>` can load a file
  path without knowing *a priori* what type of key it is (thanks to some handy
  methods within our cryptography dependency). Going forwards, we expect this
  to be the primary method of loading keys by user code that runs on "human
  time" (i.e. where some minor efficiencies are worth the convenience).

  In addition, `PKey.from_type_string <paramiko.pkey.PKey.from_type_string>`
  now exists, and is being used in some internals to load ssh-agent keys.

  As part of these changes, `~paramiko.pkey.PKey` and friends grew an
  `~paramiko.pkey.PKey.identifiers` classmethod; this is inspired by the
  `~paramiko.ecdsakey.ECDSAKey.supported_key_format_identifiers` classmethod
  (which now refers to the new method.) This also includes adding a ``.name``
  attribute to most key classes (which will eventually replace ``.get_name()``.

- :feature:`-` `~paramiko.pkey.PKey` grew a new ``.algorithm_name`` property
  which displays the key algorithm; this is typically derived from the value of
  `~paramiko.pkey.PKey.get_name`. For example, ED25519 keys have a ``get_name``
  of ``ssh-ed25519`` (the SSH protocol key type field value), and now have a
  ``algorithm_name`` of ``ED25519``.
- :feature:`-` `~paramiko.pkey.PKey` grew a new ``.fingerprint`` property which
  emits a fingerprint string matching the SHA256+Base64 values printed by
  various OpenSSH tooling (eg ``ssh-add -l``, ``ssh -v``). This is intended to
  help troubleshoot Paramiko-vs-OpenSSH behavior and will eventually replace
  the venerable ``get_fingerprint`` method.
- :bug:`- major` `~paramiko.agent.AgentKey` had a dangling Python 3
  incompatible ``__str__`` method returning bytes. This method has been
  removed, allowing the superclass' (`~paramiko.pkey.PKey`) method to run
  instead.
- :release:`3.1.0 <2023-03-10>`
- :feature:`2013` (solving :issue:`2009`, plus others) Add an explicit
  ``channel_timeout`` keyword argument to `paramiko.client.SSHClient.connect`,
  allowing users to configure the previously-hardcoded default value of 3600
  seconds. Thanks to ``@VakarisZ`` and ``@ilija-lazoroski`` for the report and
  patch, with credit to Mike Salvatore for patch review.
- :feature:`2173` Accept single tabs as field separators (in addition to
  single spaces) in `<paramiko.hostkeys.HostKeyEntry.from_line>` for parity
  with OpenSSH's KnownHosts parser. Patched by Alex Chavkin.
- :support:`2178 backported` Apply ``codespell`` to the codebase, which found a
  lot of very old minor spelling mistakes in docstrings. Also modernize many
  instances of ``*largs`` vs ``*args`` and ``**kwarg`` vs ``**kwargs``. Patch
  courtesy of Yaroslav Halchenko, with review from Brian Skinn.
- :release:`3.0.0 <2023-01-20>`
- :bug:`2110 major` Remove some unnecessary ``__repr__`` calls when handling
  bytes-vs-str conversions. This was apparently doing a lot of unintentional
  data processing, which adds up in some use cases -- such as SFTP transfers,
  which may now be significantly faster. Kudos to Shuhua Zhong for catch &
  patch.
- :bug:`2165 major` Streamline some redundant (and costly) byte conversion
  calls in the packetizer and the core SFTP module. This should lead to some
  SFTP speedups at the very least. Thanks to Alex Gaynor for the patch.
- :support:`-` ``paramiko.util.retry_on_signal`` (and any internal uses of
  same, and also any internal retries of ``EINTR`` on eg socket operations) has
  been removed. As of Python 3.5, per `PEP 475
  <https://peps.python.org/pep-0475/>`_, this functionality (and retrying
  ``EINTR`` generally) is now part of the standard library.

  .. warning::
    This change is backwards incompatible if you were explicitly
    importing/using this particular function. The observable behavior otherwise
    should not be changing.

- :support:`732` (also re: :issue:`630`) `~paramiko.config.SSHConfig` used to
  straight-up delete the ``proxycommand`` key from config lookup results when
  the source config said ``ProxyCommand none``. This has been altered to
  preserve the key and give it the Python value ``None``, thus making the
  Python representation more in line with the source config file.

  .. warning::
    This change is backwards incompatible if you were relying on the old (1.x,
    2.x) behavior for some reason (eg assuming all ``proxycommand`` values were
    valid subcommand strings).

- :support:`-` The behavior of private key classes' (ie anything inheriting
  from `~paramiko.pkey.PKey`)  private key writing methods used to perform a
  manual, extra ``chmod`` call after writing. This hasn't been strictly
  necessary since the mid 2.x release line (when key writing started giving the
  ``mode`` argument to `os.open`), and has now been removed entirely.

  This should only be observable if you were mocking Paramiko's system calls
  during your own testing, or similar.
- :support:`-` ``PKey.__cmp__`` has been removed. Ordering-oriented comparison
  of key files is unlikely to have ever made sense (the old implementation
  attempted to order by the hashes of the key material) and so we have not
  bothered setting up ``__lt__`` and friends at this time. The class continues
  to have its original ``__eq__`` untouched.

  .. warning::
    This change is backwards incompatible if you were actually trying to sort
    public key objects (directly or indirectly). Please file bug reports
    detailing your use case if you have some intractable need for this
    behavior, and we'll consider adding back the necessary Python 3 magic
    methods so that it works as before.

- :bug:`- major` A handful of lower-level classes (notably
  `paramiko.message.Message` and `paramiko.pkey.PKey`) previously returned
  `bytes` objects from their implementation of ``__str__``, even under Python
  3; and there was never any ``__bytes__`` method.

  These issues have been fixed by renaming ``__str__`` to ``__bytes__`` and
  relying on Python's default "stringification returns the output of
  ``__repr__``" behavior re: any real attempts to ``str()`` such objects.
- :support:`-` ``paramiko.common.asbytes`` has been moved to
  ``paramiko.util.asbytes``.

  .. warning::
    This change is backwards incompatible if you were directly using this
    function (which is unlikely).

- :support:`-` Remove the now irrelevant ``paramiko.py3compat`` module.

  .. warning::
    This change is backwards incompatible. Such references should be
    search-and-replaced with their modern Python 3.6+ equivalents; in some
    cases, still-useful methods or values have been moved to ``paramiko.util``
    (most) or ``paramiko.common`` (``byte_*``).

- :support:`-` Drop support for Python versions less than 3.6, including Python
  2. So long and thanks for all the fish!

  .. warning::
    This change is backwards incompatible. However, our packaging metadata has
    been updated to include ``python_requires``, so this should not cause
    breakage unless you're on an old installation method that can't read this
    metadata.

  .. note::
    As part of this change, our dependencies have been updated; eg we now
    require Cryptography>=3.3, up from 2.5.

- :release:`2.12.0 <2022-11-04>`
- :feature:`2125` (also re: :issue:`2054`) Add a ``transport_factory`` kwarg to
  `SSHClient.connect <paramiko.client.SSHClient.connect>` for advanced
  users to gain more control over early Transport setup and manipulation.
  Thanks to Noah Pederson for the patch.
- :release:`2.11.1 <2022-11-04>`
- :release:`2.10.6 <2022-11-04>`
- :bug:`1822` (via, and relating to, far too many other issues to mention here)
  Update `~paramiko.client.SSHClient` so it explicitly closes its wrapped
  socket object upon encountering socket errors at connection time. This should
  help somewhat with certain classes of memory leaks, resource warnings, and/or
  errors (though we hasten to remind everyone that Client and Transport have
  their own ``.close()`` methods for use in non-error situations!). Patch
  courtesy of ``@YoavCohen``.
- bug:`1637` (via :issue:`1599`) Raise `~paramiko.ssh_exception.SSHException`
  explicitly when blank private key data is loaded, instead of the natural
  result of ``IndexError``. This should help more bits of Paramiko or
  Paramiko-adjacent codebases to correctly handle this class of error. Credit:
  Nicholas Dietz.
- :release:`2.11.0 <2022-05-16>`
- :release:`2.10.5 <2022-05-16>`
- :release:`2.9.5 <2022-05-16>`
- :bug:`1933` Align signature verification algorithm with OpenSSH re:
  zero-padding signatures which don't match their nominal size/length. This
  shouldn't affect most users, but will help Paramiko-implemented SSH servers
  handle poorly behaved clients such as PuTTY. Thanks to Jun Omae for catch &
  patch.
- :bug:`2017` OpenSSH 7.7 and older has a bug preventing it from understanding
  how to perform SHA2 signature verification for RSA certificates (specifically
  certs - not keys), so when we added SHA2 support it broke all clients using
  RSA certificates with these servers. This has been fixed in a manner similar
  to what OpenSSH's own client does: a version check is performed and the
  algorithm used is downgraded if needed. Reported by Adarsh Chauhan, with fix
  suggested by Jun Omae.
- :support:`2038` (via :issue:`2039`) Recent versions of Cryptography have
  deprecated Blowfish algorithm support; in lieu of an easy method for users to
  remove it from the list of algorithms Paramiko tries to import and use, we've
  decided to remove it from our "preferred algorithms" list. This will both
  discourage use of a weak algorithm, and avoid warnings. Credit for
  report/patch goes to Mike Roest.
- :bug:`2008` (via :issue:`2010`) Windows-native SSH agent support as merged in
  2.10 could encounter ``Errno 22`` ``OSError`` exceptions in some scenarios
  (eg server not cleanly closing a relevant named pipe). This has been worked
  around and should be less problematic. Reported by Danilo Campana Fuchs and
  patched by Jun Omae.
- :release:`2.10.4 <2022-04-25>`
- :release:`2.9.4 <2022-04-25>`
- :support:`1838 backported` (via :issue:`1870`/:issue:`2028`) Update
  ``camelCase`` method calls against the ``threading`` module to be
  ``snake_case``; this and related tweaks should fix some deprecation warnings
  under Python 3.10. Thanks to Karthikeyan Singaravelan for the report,
  ``@Narendra-Neerukonda`` for the patch, and to Thomas Grainger and Jun Omae
  for patch workshopping.
- :feature:`1951` Add SSH config token expansion (eg ``%h``, ``%p``) when
  parsing ``ProxyJump`` directives. Patch courtesy of Bruno Inec.
- :bug:`1964` (via :issue:`2024` as also reported in :issue:`2023`)
  `~paramiko.pkey.PKey` instances' ``__eq__`` did not have the usual safety
  guard in place to ensure they were being compared to another ``PKey`` object,
  causing occasional spurious ``BadHostKeyException`` (among other things).
  This has been fixed. Thanks to Shengdun Hua for the original report/patch and
  to Christopher Papke for the final version of the fix.
- :support:`2004` (via :issue:`2011`) Apply unittest ``skipIf`` to tests
  currently using SHA1 in their critical path, to avoid failures on systems
  starting to disable SHA1 outright in their crypto backends (eg RHEL 9).
  Report & patch via Paul Howarth.
- :bug:`2035` Servers offering certificate variants of hostkey algorithms (eg
  ``ssh-rsa-cert-v01@openssh.com``) could not have their host keys verified by
  Paramiko clients, as it only ever considered non-cert key types for that part
  of connection handshaking. This has been fixed.
- :release:`2.10.3 <2022-03-18>`
- :release:`2.9.3 <2022-03-18>`
- :bug:`1963` (via :issue:`1977`) Certificate-based pubkey auth was
  inadvertently broken when adding SHA2 support; this has been fixed. Reported
  by Erik Forsberg and fixed by Jun Omae.
- :bug:`2002` (via :issue:`2003`) Switch from module-global to thread-local
  storage when recording thread IDs for a logging helper; this should avoid one
  flavor of memory leak for long-running processes. Catch & patch via Richard
  Kojedzinszky.
- :release:`2.10.2 <2022-03-14>`
- :bug:`2001` Fix Python 2 compatibility breakage introduced in 2.10.1. Spotted
  by Christian Hammond.

  .. warning::
      This is almost certainly the last time we will fix Python 2 related
      errors! Please see `the roadmap
      <https://bitprophet.org/projects/#roadmap>`_.

- :release:`2.10.1 <2022-03-11>`
- :bug:`- (2.10+)` (`CVE-2022-24302
  <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24302>`_) Creation
  of new private key files using `~paramiko.pkey.PKey` subclasses was subject
  to a race condition between file creation & mode modification, which could be
  exploited by an attacker with knowledge of where the Paramiko-using code
  would write out such files.

  This has been patched by using `os.open` and `os.fdopen` to ensure new files
  are opened with the correct mode immediately. We've left the subsequent
  explicit ``chmod`` in place to minimize any possible disruption, though it
  may get removed in future backwards-incompatible updates.

  Thanks to Jan Schejbal for the report & feedback on the solution, and to
  Jeremy Katz at Tidelift for coordinating the disclosure.
- :release:`2.10.0 <2022-03-11>`
- :feature:`1976` Add support for the ``%C`` token when parsing SSH config
  files. Foundational PR submitted by ``@jbrand42``.
- :feature:`1509` (via :issue:`1868`, :issue:`1837`) Add support for OpenSSH's
  Windows agent as a fallback when Putty/WinPageant isn't available or
  functional. Reported by ``@benj56`` with patches/PRs from ``@lewgordon`` and
  Patrick Spendrin.
- :bug:`892 major` Significantly speed up low-level read/write actions on
  `~paramiko.sftp_file.SFTPFile` objects by using `bytearray`/`memoryview`.
  This is unlikely to change anything for users of the higher level methods
  like `SFTPClient.get <paramiko.sftp_client.SFTPClient.get>` or
  `SFTPClient.getfo <paramiko.sftp_client.SFTPClient.getfo>`, but users of
  `SFTPClient.open <paramiko.sftp_client.SFTPClient.open>` will likely see
  orders of magnitude improvements for files larger than a few megabytes in
  size.

  Thanks to ``@jkji`` for the original report and to Sevastian Tchernov for the
  patch.
- :support:`1985` Add ``six`` explicitly to install-requires; it snuck into
  active use at some point but has only been indicated by transitive dependency
  on ``bcrypt`` until they somewhat-recently dropped it. This will be
  short-lived until we `drop Python 2
  support <https://bitprophet.org/projects/#roadmap>`_. Thanks to Sondre
  Lillebø Gundersen for catch & patch.
- :release:`2.9.2 <2022-01-08>`
- :bug:`-` Connecting to servers which support ``server-sig-algs`` but which
  have no overlap between that list and what a Paramiko client supports, now
  raise an exception instead of defaulting to ``rsa-sha2-512`` (since the use
  of ``server-sig-algs`` allows us to know what the server supports).
- :bug:`-` Enhanced log output when connecting to servers that do not support
  ``server-sig-algs`` extensions, making the new-as-of-2.9 defaulting to SHA2
  pubkey algorithms more obvious when it kicks in.
- :release:`2.9.1 <2021-12-24>`
- :bug:`1955` Server-side support for ``rsa-sha2-256`` and ``ssh-rsa`` wasn't
  fully operable after 2.9.0's release (signatures for RSA pubkeys were always
  run through ``rsa-sha2-512`` instead). Report and early stab at a fix
  courtesy of Jun Omae.
- :release:`2.9.0 <2021-12-23>`
- :feature:`1643` (also :issue:`1925`, :issue:`1644`, :issue:`1326`) Add
  support for SHA-2 variants of RSA key verification algorithms (as described
  in :rfc:`8332`) as well as limited SSH extension negotiation (:rfc:`8308`).

  .. warning::
    This change is slightly backwards incompatible, insofar as action is
    required if your target systems do not support either RSA2 or the
    ``server-sig-algs`` protocol extension.

    Specifically, you need to specify ``disabled_algorithms={'keys':
    ['rsa-sha2-256', 'rsa-sha2-512']}`` in either `SSHClient
    <paramiko.client.SSHClient.__init__>` or `Transport
    <paramiko.transport.Transport.__init__>`. See below for details on why.

  How SSH servers/clients decide when and how to use this functionality can be
  complicated; Paramiko's support is as follows:

  - Client verification of server host key during key exchange will now prefer
    ``rsa-sha2-512``, ``rsa-sha2-256``, and legacy ``ssh-rsa`` algorithms, in
    that order, instead of just ``ssh-rsa``.

      - Note that the preference order of other algorithm families such as
        ``ed25519`` and ``ecdsa`` has not changed; for example, those two
        groups are still preferred over RSA.

  - Server mode will now offer all 3 RSA algorithms for host key verification
    during key exchange, similar to client mode, if it has been configured with
    an RSA host key.
  - Client mode key exchange now sends the ``ext-info-c`` flag signaling
    support for ``MSG_EXT_INFO``, and support for parsing the latter
    (specifically, its ``server-sig-algs`` flag) has been added.
  - Client mode, when performing public key authentication with an RSA key or
    cert, will act as follows:

    - In all cases, the list of algorithms to consider is based on the new
      ``preferred_pubkeys`` list (see below) and ``disabled_algorithms``
      (specifically, its ``pubkeys`` key); this list, like with host keys,
      prefers SHA2-512, SHA2-256 and SHA1, in that order.
    - When the server does not send ``server-sig-algs``, Paramiko will attempt
      the first algorithm in the above list. Clients connecting to legacy
      servers should thus use ``disabled_algorithms`` to turn off SHA2.
    - When the server does send ``server-sig-algs``, the first algorithm
      supported by both ends is used, or if there is none, it falls back to the
      previous behavior.

  - SSH agent support grew the ability to specify algorithm flags when
    requesting private key signatures; this is now used to forward SHA2
    algorithms when appropriate.
  - Server mode is now capable of pubkey auth involving SHA-2 signatures from
    clients, provided one's server implementation actually provides for doing
    so.

    - This includes basic support for sending ``MSG_EXT_INFO`` (containing
      ``server-sig-algs`` only) to clients advertising ``ext-info-c`` in their
      key exchange list.

  In order to implement the above, the following API additions were made:

  - `PKey.sign_ssh_data <paramiko.pkey.PKey>`: Grew an extra, optional
    ``algorithm`` keyword argument (defaulting to ``None`` for most subclasses,
    and to ``"ssh-rsa"`` for `~paramiko.rsakey.RSAKey`).
  - A new `~paramiko.ssh_exception.SSHException` subclass was added,
    `~paramiko.ssh_exception.IncompatiblePeer`, and is raised in all spots
    where key exchange aborts due to algorithmic incompatibility.

    - Like all other exceptions in that module, it inherits from
      ``SSHException``, and as we did not change anything else about the
      raising (i.e. the attributes and message text are the same) this change
      is backwards compatible.

  - `~paramiko.transport.Transport` grew a ``_preferred_pubkeys`` attribute and
    matching ``preferred_pubkeys`` property to match the other, kex-focused,
    such members. This allows client pubkey authentication to honor the
    ``disabled_algorithms`` feature.

  Thanks to Krisztián Kovács for the report and an early stab at a patch, as
  well as the numerous users who submitted feedback on the issue, including but
  not limited to: Christopher Rabotin, Sam Bull, and Manfred Kaiser.

- :release:`2.8.1 <2021-11-28>`
- :bug:`985` (via :issue:`992`) Fix listdir failure when server uses a locale.
  Now on Python 2.7 `SFTPAttributes <paramiko.sftp_attr.SFTPAttributes>` will
  decode abbreviated month names correctly rather than raise
  ``UnicodeDecodeError```. Patch courtesy of Martin Packman.
- :bug:`1024` Deleting items from `~paramiko.hostkeys.HostKeys` would
  incorrectly raise `KeyError` even for valid keys, due to a logic bug. This
  has been fixed. Report & patch credit: Jia Zhang.
- :bug:`1257` (also :issue:`1266`) Update RSA and ECDSA key decoding
  subroutines to correctly catch exception types thrown by modern
  versions of Cryptography (specifically ``TypeError`` and
  its internal ``UnsupportedAlgorithm``). These exception classes will now
  become `~paramiko.ssh_exception.SSHException` instances instead of bubbling
  up. Thanks to Ignat Semenov for the report and ``@tylergarcianet`` for an
  early patch.
- :bug:`-` (also :issue:`908`) Update `~paramiko.pkey.PKey` and subclasses to
  compare (``__eq__``) via direct field/attribute comparison instead of hashing
  (while retaining the existing behavior of ``__hash__`` via a slight
  refactor). Big thanks to Josh Snyder and Jun Omae for the reports, and to
  Josh Snyder for reproduction details & patch.

  .. warning::
    This fixes a security flaw! If you are running Paramiko on 32-bit systems
    with low entropy (such as any 32-bit Python 2, or a 32-bit Python 3 which
    is running with ``PYTHONHASHSEED=0``) it is possible for an attacker to
    craft a new keypair from an exfiltrated public key, which Paramiko would
    consider equal to the original key.

    This could enable attacks such as, but not limited to, the following:

    - Paramiko server processes would incorrectly authenticate the attacker
      (using their generated private key) as if they were the victim. We see
      this as the most plausible attack using this flaw.
    - Paramiko client processes would incorrectly validate a connected server
      (when host key verification is enabled) while subjected
      to a man-in-the-middle attack. This impacts more users than the
      server-side version, but also carries higher requirements for the
      attacker, namely successful DNS poisoning or other MITM techniques.

- :release:`2.8.0 <2021-10-09>`
- :support:`-` Administrivia overhaul, including but not limited to:

  - Migrate CI to CircleCI
  - Primary dev branch is now ``main`` (renamed)
  - Many README edits for clarity, modernization etc; including a bunch more
    (and consistent) status badges & unification with main project site index
  - PyPI page much more fleshed out (long_description is now filled in with the
    README; sidebar links expanded; etc)
  - flake8, pytest configs split out of setup.cfg into their own files
  - Invoke/invocations (used by maintainers/contributors) upgraded to modern
    versions

- :bug:`1462 major` (via :issue:`1882`) Newer server-side key exchange
  algorithms not intended to use SHA1 (``diffie-hellman-group14-sha256``,
  ``diffie-hellman-group16-sha512``) were incorrectly using SHA1 after all, due
  to a bug causing them to ignore the ``hash_algo`` class attribute. This has
  been corrected. Big thanks to ``@miverson`` for the report and to Benno Rice
  for the patch.
- :feature:`1846` Add a ``prefetch`` keyword argument to `SFTPClient.get <paramiko.sftp_client.SFTPClient.get>`/`SFTPClient.getfo <paramiko.sftp_client.SFTPClient.getfo>`
  so users who need to skip SFTP prefetching are able to conditionally turn it
  off. Thanks to Github user ``@h3ll0r`` for the PR.
- :release:`2.7.2 <2020-08-30>`
- :support:`- backported` Update our CI to catch issues with sdist generation,
  installation and testing.
- :support:`1727 backported` Add missing test suite fixtures directory to
  MANIFEST.in, reinstating the ability to run Paramiko's tests from an sdist
  tarball. Thanks to Sandro Tosi for reporting the issue and to Blazej Michalik
  for the PR.
- :support:`1722 backported` Remove leading whitespace from OpenSSH RSA test
  suite static key fixture, to conform better to spec. Credit: Alex Gaynor.
- :bug:`-` Fix incorrect string formatting causing unhelpful error message
  annotation when using Kerberos/GSSAPI. (Thanks, newer version of flake8!)
- :bug:`1723` Fix incorrectly swapped order of ``p`` and ``q`` numbers when
  loading OpenSSH-format RSA private keys. At minimum this should address a
  slowdown when using such keys, and it also means Paramiko works with
  Cryptography 3.1 and above (which complains strenuously when this problem
  appears). Thanks to Alex Gaynor for the patch.
- :release:`2.7.1 <2019-12-09>`
- :bug:`1567` The new-style private key format (added in 2.7) suffered from an
  unpadding bug which had been fixed earlier for Ed25519 (as that key type has
  always used the newer format). That fix has been refactored and applied to
  the base key class, courtesy of Pierce Lopez.
- :bug:`1565` (via :issue:`1566`) Fix a bug in support for ECDSA keys under the
  newly supported OpenSSH key format. Thanks to Pierce Lopez for the patch.
- :release:`2.7.0 <2019-12-03>`
- :feature:`602` (via :issue:`1343`, :issue:`1313`, :issue:`618`) Implement
  support for OpenSSH 6.5-style private key files (typically denoted as having
  ``BEGIN OPENSSH PRIVATE KEY`` headers instead of PEM format's ``BEGIN RSA
  PRIVATE KEY`` or similar). If you were getting any sort of weird auth error
  from "modern" keys generated on newer operating system releases (such as
  macOS Mojave), this is the first update to try.

  Major thanks to everyone who contributed or tested versions of the patch,
  including but not limited to: Kevin Abel, Michiel Tiller, Pierce Lopez, and
  Jared Hobbs.
- :bug:`- major` ``ssh_config`` :ref:`token expansion <TOKENS>` used a
  different method of determining the local username (``$USER`` env var),
  compared to what the (much older) client connection code does
  (``getpass.getuser``, which includes ``$USER`` but may check other variables
  first, and is generally much more comprehensive). Both modules now use
  ``getpass.getuser``.
- :feature:`-` A couple of outright `~paramiko.config.SSHConfig` parse errors
  were previously represented as vanilla ``Exception`` instances; as part of
  recent feature work a more specific exception class,
  `~paramiko.ssh_exception.ConfigParseError`, has been created. It is now also
  used in those older spots, which is naturally backwards compatible.
- :feature:`717` Implement support for the ``Match`` keyword in ``ssh_config``
  files. Previously, this keyword was simply ignored & keywords inside such
  blocks were treated as if they were part of the previous block. Thanks to
  Michael Leinartas for the initial patchset.

  .. note::
    This feature adds a new :doc:`optional install dependency </installing>`,
    `Invoke <https://www.pyinvoke.org>`_, for managing ``Match exec``
    subprocesses.

- :support:`-` Additional :doc:`installation </installing>` ``extras_require``
  "flavors" (``ed25519``, ``invoke``, and ``all``) have been added to
  our packaging metadata; see the install docs for details.
- :bug:`- major` Paramiko's use of ``subprocess`` for ``ProxyCommand`` support
  is conditionally imported to prevent issues on limited interpreter platforms
  like Google Compute Engine. However, any resulting ``ImportError`` was lost
  instead of preserved for raising (in the rare cases where a user tried
  leveraging ``ProxyCommand`` in such an environment). This has been fixed.
- :bug:`- major` Perform deduplication of ``IdentityFile`` contents during
  ``ssh_config`` parsing; previously, if your config would result in the same
  value being encountered more than once, ``IdentityFile`` would contain that
  many copies of the same string.
- :feature:`897` Implement most 'canonical hostname' ``ssh_config``
  functionality (``CanonicalizeHostname``, ``CanonicalDomains``,
  ``CanonicalizeFallbackLocal``, and ``CanonicalizeMaxDots``;
  ``CanonicalizePermittedCNAMEs`` has **not** yet been implemented). All were
  previously silently ignored. Reported by Michael Leinartas.
- :support:`-` Explicitly document :ref:`which ssh_config features we
  currently support <ssh-config-support>`. Previously users just had to guess,
  which is simply no good.
- :feature:`-` Add new convenience classmethod constructors to
  `~paramiko.config.SSHConfig`: `~paramiko.config.SSHConfig.from_text`,
  `~paramiko.config.SSHConfig.from_file`, and
  `~paramiko.config.SSHConfig.from_path`. No more annoying two-step process!
- :release:`2.6.0 <2019-06-23>`
- :feature:`1463` Add a new keyword argument to `SSHClient.connect
  <paramiko.client.SSHClient.connect>` and `~paramiko.transport.Transport`,
  ``disabled_algorithms``, which allows selectively disabling one or more
  kex/key/cipher/etc algorithms. This can be useful when disabling algorithms
  your target server (or client) does not support cleanly, or to work around
  unpatched bugs in Paramiko's own implementation thereof.
- :release:`2.5.1 <2019-06-23>`
- :release:`2.4.3 <2019-06-23>`
- :bug:`1306` (via :issue:`1400`) Fix Ed25519 key handling so certain key
  comment lengths don't cause ``SSHException("Invalid key")`` (this was
  technically a bug in how padding, or lack thereof, is
  calculated/interpreted). Thanks to ``@parke`` for the bug report & Pierce
  Lopez for the patch.
- :support:`1440` (with initial fixes via :issue:`1460`) Tweak many exception
  classes so their string representations are more human-friendly; this also
  includes incidental changes to some ``super()`` calls.

  The definitions of exceptions' ``__init__`` methods have *not* changed, nor
  have any log messages been altered, so this should be backwards compatible
  for everything except the actual exceptions' ``__str__()`` outputs.

  Thanks to Fabian Büchler for original report & Pierce Lopez for the
  foundational patch.
- :support:`1311` (for :issue:`584`, replacing :issue:`1166`) Add
  backwards-compatible support for the ``gssapi`` GSSAPI library, as the
  previous backend (``python-gssapi``) has since become defunct. This change
  also includes tests for the GSSAPI functionality.

  Big thanks to Anselm Kruis for the patch and to Sebastian Deiß (author of our
  initial GSSAPI functionality) for review.

  .. note::
     This feature also adds ``setup.py`` 'extras' support for installing
     Paramiko as ``paramiko[gssapi]``, which pulls in the optional
     dependencies you had to get by hand previously.

  .. note::
    To be very clear, this patch **does not** remove support for the older
    ``python-gssapi`` library. We *may* remove that support in a later release,
    but for now, either library will work. Please upgrade to ``gssapi`` when
    you can, however, as ``python-gssapi`` is no longer maintained upstream.

- :bug:`322 major` `SSHClient.exec_command
  <paramiko.client.SSHClient.exec_command>` previously returned a naive
  `~paramiko.channel.ChannelFile` object for its ``stdin`` value; such objects
  don't know to properly shut down the remote end's stdin when they
  ``.close()``. This lead to issues (such as hangs) when running remote
  commands that read from stdin.

  A new subclass, `~paramiko.channel.ChannelStdinFile`, has been created which
  closes remote stdin when it itself is closed.
  `~paramiko.client.SSHClient.exec_command` has been updated to use that class
  for its ``stdin`` return value.

  Thanks to Brandon Rhodes for the report & steps to reproduce.
- :release:`2.5.0 <2019-06-09>`
- :feature:`1233` (also :issue:`1229`, :issue:`1332`) Add support for
  encrypt-then-MAC (ETM) schemes (``hmac-sha2-256-etm@openssh.com``,
  ``hmac-sha2-512-etm@openssh.com``) and two newer Diffie-Hellman group key
  exchange algorithms (``group14``, using SHA256; and ``group16``, using
  SHA512). Patch courtesy of Edgar Sousa.
- :feature:`532` (via :issue:`1384` and :issue:`1258`) Add support for
  Curve25519 key exchange (aka ``curve25519-sha256@libssh.org``). Thanks to
  Alex Gaynor and Dan Fuhry for supplying patches.
- :support:`1379` (also :issue:`1369`) Raise Cryptography dependency
  requirement to version 2.5 (from 1.5) and update some deprecated uses of its
  API.

  This removes a bunch of warnings of the style
  ``CryptographyDeprecationWarning: encode_point has been deprecated on
  EllipticCurvePublicNumbers and will be removed in a future version. Please
  use EllipticCurvePublicKey.public_bytes to obtain both compressed and
  uncompressed point encoding`` and similar, which users who had eventually
  upgraded to Cryptography 2.x would encounter.

  .. warning::
    This change is backwards incompatible **if** you are unable to upgrade your
    version of Cryptography. Please see `Cryptography's own changelog
    <https://cryptography.io/en/latest/changelog/>`_ for details on what may
    change when you upgrade; for the most part the only changes involved
    dropping older Python versions (such as 2.6, 3.3, or some PyPy editions)
    which Paramiko itself has already dropped.

- :support:`1378 backported` Add support for the modern (as of Python 3.3)
  import location of ``MutableMapping`` (used in host key management) to avoid
  the old location becoming deprecated in Python 3.8. Thanks to Josh Karpel for
  catch & patch.
- :release:`2.4.2 <2018-09-18>`
- :release:`2.3.3 <2018-09-18>`
- :release:`2.2.4 <2018-09-18>`
- :release:`2.1.6 <2018-09-18>`
- :release:`2.0.9 <2018-09-18>`
- :bug:`-` Modify protocol message handling such that ``Transport`` does not
  respond to ``MSG_UNIMPLEMENTED`` with its own ``MSG_UNIMPLEMENTED``. This
  behavior probably didn't cause any outright errors, but it doesn't seem to
  conform to the RFCs and could cause (non-infinite) feedback loops in some
  scenarios (usually those involving Paramiko on both ends).
- :bug:`1283` Fix exploit (CVE-2018-1000805) in Paramiko's server mode (**not**
  client mode) where hostile clients could trick the server into thinking they
  were authenticated without actually submitting valid authentication.

  Specifically, steps have been taken to start separating client and server
  related message types in the message handling tables within ``Transport`` and
  ``AuthHandler``; this work is not complete but enough has been performed to
  close off this particular exploit (which was the only obvious such exploit
  for this particular channel).

  Thanks to Daniel Hoffman for the detailed report.
- :support:`1292 backported (<2.4)` Backport changes from :issue:`979` (added
  in Paramiko
  2.3) to Paramiko 2.0-2.2, using duck-typing to preserve backwards
  compatibility. This allows these older versions to use newer Cryptography
  sign/verify APIs when available, without requiring them (as is the case with
  Paramiko 2.3+).

  Practically speaking, this change prevents spamming of
  ``CryptographyDeprecationWarning`` notices which pop up in the above scenario
  (older Paramiko, newer Cryptography).

  .. note::
    This is a no-op for Paramiko 2.3+, which have required newer Cryptography
    releases since they were released.

- :support:`1291 backported (<2.4)` Backport pytest support and application of
  the ``black`` code formatter (both of which previously only existed in the
  2.4 branch and above) to everything 2.0 and newer. This makes back/forward
  porting bugfixes significantly easier.
- :support:`1262 backported` Add ``*.pub`` files to the MANIFEST so distributed
  source packages contain some necessary test assets. Credit: Alexander
  Kapshuna.
- :feature:`1212` Updated `SSHConfig.lookup <paramiko.config.SSHConfig.lookup>`
  so it returns a new, type-casting-friendly dict subclass
  (`~paramiko.config.SSHConfigDict`) in lieu of dict literals. This ought to be
  backwards compatible, and allows an easier way to check boolean or int type
  ``ssh_config`` values. Thanks to Chris Rose for the patch.
- :support:`1191` Update our install docs with (somewhat) recently added
  additional dependencies; we previously only required Cryptography, but the
  docs never got updated after we incurred ``bcrypt`` and ``pynacl``
  requirements for Ed25519 key support.

  Additionally, ``pyasn1`` was never actually hard-required; it was necessary
  during a development branch, and is used by the optional GSSAPI support, but
  is not required for regular installation. Thus, it has been removed from our
  ``setup.py`` and its imports in the GSSAPI code made optional.

  Credit to ``@stevenwinfield`` for highlighting the outdated install docs.
- :release:`2.4.1 <2018-03-12>`
- :release:`2.3.2 <2018-03-12>`
- :release:`2.2.3 <2018-03-12>`
- :release:`2.1.5 <2018-03-12>`
- :release:`2.0.8 <2018-03-12>`
- :release:`1.18.5 <2018-03-12>`
- :release:`1.17.6 <2018-03-12>`
- :bug:`1175 (1.17+)` Fix a security flaw (CVE-2018-7750) in Paramiko's server
  mode (emphasis on **server** mode; this does **not** impact *client* use!)
  where authentication status was not checked before processing channel-open
  and other requests typically only sent after authenticating. Big thanks to
  Matthijs Kooijman for the report.
- :bug:`1168` Add newer key classes for Ed25519 and ECDSA to
  ``paramiko.__all__`` so that code introspecting that attribute, or using
  ``from paramiko import *`` (such as some IDEs) sees them. Thanks to
  ``@patriksevallius`` for the patch.
- :bug:`1039` Ed25519 auth key decryption raised an unexpected exception when
  given a unicode password string (typical in python 3). Report by Theodor van
  Nahl and fix by Pierce Lopez.
- :release:`2.4.0 <2017-11-14>`
- :feature:`-` Add a new ``passphrase`` kwarg to `SSHClient.connect
  <paramiko.client.SSHClient.connect>` so users may disambiguate key-decryption
  passphrases from password-auth passwords. (This is a backwards compatible
  change; ``password`` will still pull double duty as a passphrase when
  ``passphrase`` is not given.)
- :support:`-` Update ``tearDown`` of client test suite to avoid hangs due to
  eternally blocking ``accept()`` calls on the internal server thread (which
  can occur when test code raises an exception before actually connecting to
  the server.)
- :bug:`1108 (1.17+)` Rename a private method keyword argument (which was named
  ``async``) so that we're compatible with the upcoming Python 3.7 release
  (where ``async`` is a new keyword.) Thanks to ``@vEpiphyte`` for the report.
- :support:`1100` Updated the test suite & related docs/metadata/config to be
  compatible with pytest instead of using the old, custom, crufty
  unittest-based ``test.py``.

  This includes marking known-slow tests (mostly the SFTP ones) so they can be
  filtered out by ``inv test``'s default behavior; as well as other minor
  tweaks to test collection and/or display (for example, GSSAPI tests are
  collected, but skipped, instead of not even being collected by default as in
  ``test.py``.)
- :support:`- backported` Include LICENSE file in wheel archives.
- :support:`1070` Drop Python 2.6 and Python 3.3 support; now only 2.7 and 3.4+
  are supported. If you're unable to upgrade from 2.6 or 3.3, please stick to
  the Paramiko 2.3.x (or below) release lines.
- :release:`2.3.1 <2017-09-22>`
- :bug:`1071` Certificate support broke the no-certificate case for Ed25519
  keys (symptom is an ``AttributeError`` about ``public_blob``.) This went
  uncaught due to cert autoload behavior (i.e. our test suite never actually
  ran the no-cert case, because the cert existed!) Both issues have been fixed.
  Thanks to John Hu for the report.
- :release:`2.3.0 <2017-09-18>`
- :release:`2.2.2 <2017-09-18>`
- :release:`2.1.4 <2017-09-18>`
- :release:`2.0.7 <2017-09-18>`
- :release:`1.18.4 <2017-09-18>`
- :bug:`1065` Add rekeying support to GSSAPI connections, which was erroneously
  missing. Without this fix, any attempt to renegotiate the transport keys for
  a ``gss-kex``-authed `~paramiko.transport.Transport` would cause a MIC
  failure and terminate the connection. Thanks to Sebastian Deiß and Anselm
  Kruis for the patch.
- :feature:`1063` Add a ``gss_trust_dns`` option to ``Client`` and
  ``Transport`` to allow explicitly setting whether or not DNS canonicalization
  should occur when using GSSAPI. Thanks to Richard E. Silverman for the report
  & Sebastian Deiß for initial patchset.
- :bug:`1061` Clean up GSSAPI authentication procedures so they do not prevent
  normal fallback to other authentication methods on failure. (In other words,
  presence of GSSAPI functionality on a target server precluded use of _any_
  other auth type if the user was unable to pass GSSAPI auth.) Patch via Anselm
  Kruis.
- :bug:`1060` Fix key exchange (kex) algorithm list for GSSAPI authentication;
  previously, the list used solely out-of-date algorithms, and now contains
  newer ones listed preferentially before the old. Credit: Anselm Kruis.
- :bug:`1055 (1.17+)` (also :issue:`1056`, :issue:`1057`, :issue:`1058`,
  :issue:`1059`) Fix up host-key checking in our GSSAPI support, which was
  previously using an incorrect API call. Thanks to Anselm Kruis for the
  patches.
- :bug:`945 (1.18+)` (backport of :issue:`910` and re: :issue:`865`) SSHClient
  now requests the type of host key it has (e.g. from known_hosts) and does not
  consider a different type to be a "Missing" host key. This fixes a common
  case where an ECDSA key is in known_hosts and the server also has an RSA host
  key. Thanks to Pierce Lopez.
- :support:`979` Update how we use `Cryptography <https://cryptography.io>`_'s
  signature/verification methods so we aren't relying on a deprecated API.
  Thanks to Paul Kehrer for the patch.

  .. warning::
    This bumps the minimum Cryptography version from 1.1 to 1.5. Such an
    upgrade should be backwards compatible and easy to do. See `their changelog
    <https://cryptography.io/en/latest/changelog/>`_ for additional details.
- :support:`-` Ed25519 keys never got proper API documentation support; this
  has been fixed.
- :feature:`1026` Update `~paramiko.ed25519key.Ed25519Key` so its constructor
  offers the same ``file_obj`` parameter as its sibling key classes. Credit:
  Michal Kuffa.
- :feature:`1013` Added pre-authentication banner support for the server
  interface (`ServerInterface.get_banner
  <paramiko.server.ServerInterface.get_banner>` plus related support in
  ``Transport/AuthHandler``.) Patch courtesy of Dennis Kaarsemaker.
- :bug:`60 major` (via :issue:`1037`) Paramiko originally defaulted to zlib
  compression level 9 (when one connects with ``compression=True``; it defaults
  to off.) This has been found to be quite wasteful and tends to cause much
  longer transfers in most cases, than is necessary.

  OpenSSH defaults to compression level 6, which is a much more reasonable
  setting (nearly identical compression characteristics but noticeably,
  sometimes significantly, faster transmission); Paramiko now uses this value
  instead.

  Thanks to Damien Dubé for the report and ``@DrNeutron`` for investigating &
  submitting the patch.
- :support:`-` Display exception type and message when logging auth-rejection
  messages (ones reading ``Auth rejected: unsupported or mangled public key``);
  previously this error case had a bare except and did not display exactly why
  the key failed. It will now append info such as ``KeyError:
  'some-unknown-type-string'`` or similar.
- :feature:`1042` (also partially :issue:`531`) Implement basic client-side
  certificate authentication (as per the OpenSSH vendor extension.)

  The core implementation is `PKey.load_certificate
  <paramiko.pkey.PKey.load_certificate>` and its corresponding ``.public_blob``
  attribute on key objects, which is honored in the auth and transport modules.
  Additionally, `SSHClient.connect <paramiko.client.SSHClient.connect>` will
  now automatically load certificate data alongside private key data when one
  has appropriately-named cert files (e.g. ``id_rsa-cert.pub``) - see its
  docstring for details.

  Thanks to Jason Rigby for a first draft (:issue:`531`) and to Paul Kapp for
  the second draft, upon which the current functionality has been based (with
  modifications.)

  .. note::
    This support is client-focused; Paramiko-driven server code is capable of
    handling cert-bearing pubkey auth packets, *but* it does not interpret any
    cert-specific fields, so the end result is functionally identical to a
    vanilla pubkey auth process (and thus requires e.g. prepopulated
    authorized-keys data.) We expect full server-side cert support to follow
    later.

- :support:`1041` Modify logic around explicit disconnect
  messages, and unknown-channel situations, so that they rely on centralized
  shutdown code instead of running their own. This is at worst removing some
  unnecessary code, and may help with some situations where Paramiko hangs at
  the end of a session. Thanks to Paul Kapp for the patch.
- :support:`1012` (via :issue:`1016`) Enhance documentation around the new
  `SFTP.posix_rename <paramiko.sftp_client.SFTPClient.posix_rename>` method so
  it's referenced in the 'standard' ``rename`` method for increased visibility.
  Thanks to Marius Flage for the report.
- :release:`2.2.1 <2017-06-13>`
- :bug:`993` Ed25519 host keys were not comparable/hashable, causing an
  exception if such a key existed in a ``known_hosts`` file. Thanks to Oleh
  Prypin for the report and Pierce Lopez for the fix.
- :bug:`990` The (added in 2.2.0) ``bcrypt`` dependency should have been on
  version 3.1.3 or greater (was initially set to 3.0.0 or greater.) Thanks to
  Paul Howarth for the report.
- :release:`2.2.0 <2017-06-09>`
- :release:`2.1.3 <2017-06-09>`
- :release:`2.0.6 <2017-06-09>`
- :release:`1.18.3 <2017-06-09>`
- :release:`1.17.5 <2017-06-09>`
- :bug:`865` SSHClient now requests the type of host key it has (e.g. from
  known_hosts) and does not consider a different type to be a "Missing" host
  key. This fixes a common case where an ECDSA key is in known_hosts and the
  server also has an RSA host key. Thanks to Pierce Lopez.
- :support:`906 (1.18+)` Clean up a handful of outdated imports and related
  tweaks. Thanks to Pierce Lopez.
- :bug:`984` Enhance default cipher preference order such that
  ``aes(192|256)-cbc`` are preferred over ``blowfish-cbc``. Thanks to Alex
  Gaynor.
- :bug:`971 (1.17+)` Allow any type implementing the buffer API to be used with
  `BufferedFile <paramiko.file.BufferedFile>`, `Channel
  <paramiko.channel.Channel>`, and `SFTPFile <paramiko.sftp_file.SFTPFile>`.
  This resolves a regression introduced in 1.13 with the Python 3 porting
  changes, when using types such as ``memoryview``. Credit: Martin Packman.
- :bug:`741` (also :issue:`809`, :issue:`772`; all via :issue:`912`) Writing
  encrypted/password-protected private key files was silently broken since 2.0
  due to an incorrect API call; this has been fixed.

  Includes a directly related fix, namely adding the ability to read
  ``AES-256-CBC`` ciphered private keys (which is now what we tend to write out
  as it is Cryptography's default private key cipher.)

  Thanks to ``@virlos`` for the original report, Chris Harris and ``@ibuler``
  for initial draft PRs, and ``@jhgorrell`` for the final patch.
- :feature:`65` (via :issue:`471`) Add support for OpenSSH's SFTP
  ``posix-rename`` protocol extension (section 3.3 of `OpenSSH's protocol
  extension document
  <http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=1.31>`_),
  via a new ``posix_rename`` method in `SFTPClient
  <paramiko.sftp_client.SFTPClient.posix_rename>` and `SFTPServerInterface
  <paramiko.sftp_si.SFTPServerInterface.posix_rename>`. Thanks to Wren Turkal
  for the initial patch & Mika Pflüger for the enhanced, merged PR.
- :feature:`869` Add an ``auth_timeout`` kwarg to `SSHClient.connect
  <paramiko.client.SSHClient.connect>` (default: 30s) to avoid hangs when the
  remote end becomes unresponsive during the authentication step. Credit to
  ``@timsavage``.

  .. note::
    This technically changes behavior, insofar as very slow auth steps >30s
    will now cause timeout exceptions instead of completing. We doubt most
    users will notice; those affected can simply give a higher value to
    ``auth_timeout``.

- :support:`921` Tighten up the ``__hash__`` implementation for various key
  classes; less code is good code. Thanks to Francisco Couzo for the patch.
- :support:`956 backported (1.17+)` Switch code coverage service from
  coveralls.io to codecov.io (& then disable the latter's auto-comments.)
  Thanks to Nikolai Røed Kristiansen for the patch.
- :bug:`983` Move ``sha1`` above the now-arguably-broken ``md5`` in the list of
  preferred MAC algorithms, as an incremental security improvement for users
  whose target systems offer both. Credit: Pierce Lopez.
- :bug:`667` The RC4/arcfour family of ciphers has been broken since version
  2.0; but since the algorithm is now known to be completely insecure, we are
  opting to remove support outright instead of fixing it. Thanks to Alex Gaynor
  for catch & patch.
- :feature:`857` Allow `SSHClient.set_missing_host_key_policy
  <paramiko.client.SSHClient.set_missing_host_key_policy>` to accept policy
  classes _or_ instances, instead of only instances, thus fixing a
  long-standing gotcha for unaware users.
- :feature:`951` Add support for ECDH key exchange (kex), specifically the
  algorithms ``ecdh-sha2-nistp256``, ``ecdh-sha2-nistp384``, and
  ``ecdh-sha2-nistp521``. They now come before the older ``diffie-hellman-*``
  family of kex algorithms in the preferred-kex list. Thanks to Shashank
  Veerapaneni for the patch & Pierce Lopez for a follow-up.
- :support:`- backported` A big formatting pass to clean up an enormous number
  of invalid Sphinx reference links, discovered by switching to a modern,
  rigorous nitpicking doc-building mode.
- :bug:`900` (via :issue:`911`) Prefer newer ``ecdsa-sha2-nistp`` keys over RSA
  and DSA keys during host key selection. This improves compatibility with
  OpenSSH, both in terms of general behavior, and also re: ability to properly
  leverage OpenSSH-modified ``known_hosts`` files. Credit: ``@kasdoe`` for
  original report/PR and Pierce Lopez for the second draft.
- :bug:`794` (via :issue:`981`) Prior support for ``ecdsa-sha2-nistp(384|521)``
  algorithms didn't fully extend to covering host keys, preventing connection
  to hosts which only offer these key types and no others. This is now fixed.
  Thanks to ``@ncoult`` and ``@kasdoe`` for reports and Pierce Lopez for the
  patch.
- :feature:`325` (via :issue:`972`) Add Ed25519 support, for both host keys
  and user authentication. Big thanks to Alex Gaynor for the patch.

  .. note::
    This change adds the ``bcrypt`` and ``pynacl`` Python libraries as
    dependencies. No C-level dependencies beyond those previously required (for
    Cryptography) have been added.

- :support:`974 backported` Overhaul the codebase to be PEP-8, etc, compliant
  (i.e. passes the maintainer's preferred `flake8 <http://flake8.pycqa.org/>`_
  configuration) and add a ``flake8`` step to the Travis config. Big thanks to
  Dorian Pula!
- :bug:`949 (1.17+)` SSHClient and Transport could cause a memory leak if
  there's a connection problem or protocol error, even if ``Transport.close()``
  is called. Thanks Kyle Agronick for the discovery and investigation, and
  Pierce Lopez for assistance.
- :bug:`683 (1.17+)` Make ``util.log_to_file`` append instead of replace.
  Thanks to ``@vlcinsky`` for the report.
- :release:`2.1.2 <2017-02-20>`
- :release:`2.0.5 <2017-02-20>`
- :release:`1.18.2 <2017-02-20>`
- :release:`1.17.4 <2017-02-20>`
- :bug:`853 (1.17+)` Tweak how `RSAKey.__str__ <paramiko.rsakey.RSAKey>`
  behaves so it doesn't cause ``TypeError`` under Python 3. Thanks to Francisco
  Couzo for the report.
- :bug:`862 (1.17+)` (via :issue:`863`) Avoid test suite exceptions on
  platforms lacking ``errno.ETIME`` (which seems to be some FreeBSD and some
  Windows environments.) Thanks to Sofian Brabez.
- :bug:`44 (1.17+)` (via :issue:`891`) `SSHClient <paramiko.client.SSHClient>`
  now gives its internal `Transport <paramiko.transport.Transport>` a handle on
  itself, preventing garbage collection of the client until the session is
  closed. Without this, some code which returns stream or transport objects
  without the client that generated them, would result in premature session
  closure when the client was GCd. Credit: ``@w31rd0`` for original report,
  Omer Anson for the patch.
- :bug:`713 (<2.0)` (via :issue:`714` and :issue:`889`) Don't pass
  initialization vectors to PyCrypto when dealing with counter-mode ciphers;
  newer PyCrypto versions throw an exception otherwise (older ones simply
  ignored this parameter altogether). Thanks to ``@jmh045000`` for report &
  patches.
- :bug:`895 (1.17+)` Fix a bug in server-mode concerning multiple interactive
  auth steps (which were incorrectly responded to). Thanks to Dennis
  Kaarsemaker for catch & patch.
- :support:`866 backported (1.17+)` (also :issue:`838`) Remove an old
  test-related file we don't support, and add PyPy to Travis-CI config. Thanks
  to Pierce Lopez for the final patch and Pedro Rodrigues for an earlier
  edition.
- :release:`2.1.1 <2016-12-12>`
- :release:`2.0.4 <2016-12-12>`
- :release:`1.18.1 <2016-12-12>`
- :bug:`859 (1.18+)` (via :issue:`860`) A tweak to the original patch
  implementing :issue:`398` was not fully applied, causing calls to
  `~paramiko.client.SSHClient.invoke_shell` to fail with ``AttributeError``.
  This has been fixed. Patch credit: Kirk Byers.
- :bug:`-` Accidentally merged the new features from 1.18.0 into the
  2.0.x bugfix-only branch. This included merging a bug in one of those new
  features (breaking `~paramiko.client.SSHClient.invoke_shell` with an
  ``AttributeError``.) The offending code has been stripped out of the 2.0.x
  line (but of course, remains in 2.1.x and above.)
- :bug:`859` (via :issue:`860`) A tweak to the original patch implementing
  :issue:`398` was not fully applied, causing calls to
  `~paramiko.client.SSHClient.invoke_shell` to fail with ``AttributeError``.
  This has been fixed. Patch credit: Kirk Byers.
- :release:`2.1.0 <2016-12-09>`
- :release:`2.0.3 <2016-12-09>`
- :release:`1.18.0 <2016-12-09>`
- :release:`1.17.3 <2016-12-09>`
- :bug:`802 (1.17+)` (via :issue:`804`) Update our vendored Windows API module
  to address errors of the form ``AttributeError: 'module' object has no
  attribute 'c_ssize_t'``. Credit to Jason R. Coombs.
- :bug:`824 (1.17+)` Fix the implementation of ``PKey.write_private_key_file``
  (this method is only publicly defined on subclasses; the fix was in the
  private real implementation) so it passes the correct params to ``open()``.
  This bug apparently went unnoticed and unfixed for 12 entire years. Congrats
  to John Villalovos for noticing & submitting the patch!
- :support:`801 backported (1.17+)` Skip a Unix-only test when on Windows;
  thanks to Gabi Davar.
- :support:`792 backported (1.17+)` Minor updates to the README and demos;
  thanks to Alan Yee.
- :feature:`780 (1.18+)` (also :issue:`779`, and may help users affected by
  :issue:`520`) Add an optional ``timeout`` parameter to
  `Transport.start_client <paramiko.transport.Transport.start_client>` (and
  feed it the value of the configured connection timeout when used within
  `SSHClient <paramiko.client.SSHClient>`.) This helps prevent situations where
  network connectivity isn't timing out, but the remote server is otherwise
  unable to service the connection in a timely manner. Credit to
  ``@sanseihappa``.
- :bug:`742` (also re: :issue:`559`) Catch ``AssertionError`` thrown by
  Cryptography when attempting to load bad ECDSA keys, turning it into an
  ``SSHException``. This moves the behavior in line with other "bad keys"
  situations, re: Paramiko's main auth loop. Thanks to MengHuan Yu for the
  patch.
- :bug:`789 (1.17+)` Add a missing ``.closed`` attribute (plus ``._closed``
  because reasons) to `ProxyCommand <paramiko.proxy.ProxyCommand>` so the
  earlier partial fix for :issue:`520` works in situations where one is
  gatewaying via ``ProxyCommand``.
- :bug:`334 (1.17+)` Make the ``subprocess`` import in ``proxy.py`` lazy so
  users on platforms without it (such as Google App Engine) can import Paramiko
  successfully. (Relatedly, make it easier to tweak an active socket check
  timeout  [in `Transport <paramiko.transport.Transport>`] which was previously
  hardcoded.) Credit: Shinya Okano.
- :support:`854 backported (1.17+)` Fix incorrect docstring/param-list for
  `Transport.auth_gssapi_keyex
  <paramiko.transport.Transport.auth_gssapi_keyex>` so it matches the real
  signature. Caught by ``@Score_Under``.
- :bug:`681 (1.17+)` Fix a Python3-specific bug re: the handling of read
  buffers when using ``ProxyCommand``. Thanks to Paul Kapp for catch & patch.
- :feature:`398 (1.18+)` Add an ``environment`` dict argument to
  `Client.exec_command <paramiko.client.SSHClient.exec_command>` (plus the
  lower level `Channel.update_environment
  <paramiko.channel.Channel.update_environment>` and
  `Channel.set_environment_variable
  <paramiko.channel.Channel.set_environment_variable>` methods) which
  implements the ``env`` SSH message type. This means the remote shell
  environment can be set without the use of ``VARNAME=value`` shell tricks,
  provided the server's ``AcceptEnv`` lists the variables you need to set.
  Thanks to Philip Lorenz for the pull request.
- :support:`819 backported (>=1.15,<2.0)` Document how lacking ``gmp`` headers
  at install time can cause a significant performance hit if you build PyCrypto
  from source. (Most system-distributed packages already have this enabled.)
- :release:`2.0.2 <2016-07-25>`
- :release:`1.17.2 <2016-07-25>`
- :release:`1.16.3 <2016-07-25>`
- :bug:`673 (1.16+)` (via :issue:`681`) Fix protocol banner read errors
  (``SSHException``) which would occasionally pop up when using
  ``ProxyCommand`` gatewaying. Thanks to ``@Depado`` for the initial report and
  Paul Kapp for the fix.
- :bug:`774 (1.16+)` Add a ``_closed`` private attribute to
  `~paramiko.channel.Channel` objects so that they continue functioning when
  used as proxy sockets under Python 3 (e.g. as ``direct-tcpip`` gateways for
  other Paramiko connections.)
- :bug:`758 (1.16+)` Apply type definitions to ``_winapi`` module from
  `jaraco.windows <https://github.com/jaraco/jaraco.windows>`_ 3.6.1. This
  should address issues on Windows platforms that often result in errors like
  ``ArgumentError: [...] int too long to convert``. Thanks to ``@swohlerLL``
  for the report and Jason R. Coombs for the patch.
- :release:`2.0.1 <2016-06-21>`
- :release:`1.17.1 <2016-06-21>`
- :release:`1.16.2 <2016-06-21>`
- :bug:`520 (1.16+)` (Partial fix) Fix at least one instance of race condition
  driven threading hangs at end of the Python interpreter session. (Includes a
  docs update as well - always make sure to ``.close()`` your clients!)
- :bug:`537 (1.16+)` Fix a bug in `BufferedPipe.set_event
  <paramiko.buffered_pipe.BufferedPipe.set_event>` which could cause
  deadlocks/hangs when one uses `select.select` against
  `~paramiko.channel.Channel` objects (or otherwise calls `Channel.fileno
  <paramiko.channel.Channel.fileno>` after the channel has closed). Thanks to
  Przemysław Strzelczak for the report & reproduction case, and to Krzysztof
  Rusek for the fix.
- :release:`2.0.0 <2016-04-28>`
- :release:`1.17.0 <2016-04-28>`
- :release:`1.16.1 <2016-04-28>`
- :release:`1.15.5 <2016-04-28>`
- :feature:`731` (working off the earlier :issue:`611`) Add support for 384-
  and 512-bit elliptic curve groups in ECDSA key types (aka
  ``ecdsa-sha2-nistp384`` / ``ecdsa-sha2-nistp521``). Thanks to Michiel Tiller
  and ``@CrazyCasta`` for the patches.
- :bug:`670` Due to an earlier bugfix, less-specific ``Host`` blocks'
  ``ProxyCommand`` values were overriding ``ProxyCommand none`` in
  more-specific ``Host`` blocks. This has been fixed in a backwards compatible
  manner (i.e. ``ProxyCommand none`` continues to appear as a total lack of any
  ``proxycommand`` key in parsed config structures). Thanks to Pat Brisbin for
  the catch.
- :bug:`676` (via :issue:`677`) Fix a backwards incompatibility issue that
  cropped up in `SFTPFile.prefetch <paramiko.sftp_file.SFTPFile.prefetch>` re:
  the erroneously non-optional ``file_size`` parameter. Should only affect
  users who manually call ``prefetch``. Thanks to ``@stevevanhooser`` for catch
  & patch.
- :feature:`394` Replace PyCrypto with the Python Cryptographic Authority
  (PyCA) 'Cryptography' library suite. This improves security, installability,
  and performance; adds PyPy support; and much more.

  There aren't enough ways to thank Alex Gaynor for all of his work on this,
  and then his patience while the maintainer let his PR grow moss for a year
  and change. Paul Kehrer came in with an assist, and I think I saw Olle
  Lundberg, ``@techtonik`` and ``@johnthagen`` supplying backup as well. Thanks
  to all!

  .. warning::
    **This is a backwards incompatible change.**

    However, **it should only affect installation** requirements; **no API
    changes are intended or expected**. Please report any such breakages as
    bugs.

    See our updated :doc:`installation docs <installing>` for details on what
    is now required to install Paramiko; many/most users should be able to
    simply ``pip install -U paramiko`` (especially if you **upgrade to pip
    8**).

- :bug:`577` (via :issue:`578`; should also fix :issue:`718`, :issue:`560`) Fix
  stalled/hung SFTP downloads by cleaning up some threading lock issues. Thanks
  to Stephen C. Pope for the patch.
- :bug:`716` Fix a Python 3 compatibility issue when handling two-factor
  authentication. Thanks to Mateusz Kowalski for the catch & original patch.
- :support:`729 backported (>=1.15,<2.0)` Clean up ``setup.py`` to always use
  ``setuptools``, not doing so was a historical artifact from bygone days.
  Thanks to Alex Gaynor.
- :bug:`649 major (==1.17)` Update the module in charge of handling SSH moduli
  so it's consistent with OpenSSH behavior re: prime number selection. Thanks
  to Damien Tournoud for catch & patch.
- :bug:`617` (aka `fabric/fabric#1429
  <https://github.com/fabric/fabric/issues/1429>`_; via :issue:`679`; related:
  :issue:`678`, :issue:`685`, :issue:`615` & :issue:`616`) Fix up
  `~paramiko.ssh_exception.NoValidConnectionsError` so it pickles correctly,
  and fix a related Python 3 compatibility issue. Thanks to Rebecca Schlussel
  for the report & Marius Gedminas for the patch.
- :bug:`613` (via :issue:`619`) Update to ``jaraco.windows`` 3.4.1 to fix some
  errors related to ``ctypes`` on Windows platforms. Credit to Jason R. Coombs.
- :support:`621 backported (>=1.15,<2.0)` Annotate some public attributes on
  `~paramiko.channel.Channel` such as ``.closed``. Thanks to Sergey Vasilyev
  for the report.
- :bug:`632` Fix logic bug in the SFTP client's callback-calling functionality;
  previously there was a chance the given callback would fire twice at the end
  of a transfer. Thanks to ``@ab9-er`` for catch & original patch.
- :support:`612 backported (>=1.15,<2.0)` Identify & work around a race
  condition in the test for handshake timeouts, which was causing frequent test
  failures for a subset of contributors as well as Travis-CI (usually, but not
  always, limited to Python 3.5). Props to Ed Kellett for assistance during
  some of the troubleshooting.
- :support:`697 backported (>=1.15,<2.0)` Remove whitespace in our
  ``setup.py``'s ``install_requires`` as it triggers occasional bugs in some
  versions of ``setuptools``. Thanks to Justin Lecher for catch & original
  patch.
- :bug:`499` Strip trailing/leading whitespace from lines when parsing SSH
  config files - this brings things in line with OpenSSH behavior. Thanks to
  Alfredo Esteban for the original report and Nick Pillitteri for the patch.
- :bug:`652` Fix behavior of ``gssapi-with-mic`` auth requests so they fail
  gracefully (allowing followup via other auth methods) instead of raising an
  exception. Patch courtesy of ``@jamercee``.
- :feature:`588 (==1.17)` Add missing file-like object methods for
  `~paramiko.file.BufferedFile` and `~paramiko.sftp_file.SFTPFile`. Thanks to
  Adam Meily for the patch.
- :support:`636 backported (>=1.15,<2.0)` Clean up and enhance the README (and
  rename it to ``README.rst`` from just ``README``). Thanks to ``@LucasRMehl``.
- :release:`1.16.0 <2015-11-04>`
- :bug:`194 major` (also :issue:`562`, :issue:`530`, :issue:`576`) Streamline
  use of ``stat`` when downloading SFTP files via `SFTPClient.get
  <paramiko.sftp_client.SFTPClient.get>`; this avoids triggering bugs in some
  off-spec SFTP servers such as IBM Sterling. Thanks to ``@muraleee`` for the
  initial report and to Torkil Gustavsen for the patch.
- :feature:`467` (also :issue:`139`, :issue:`412`) Fully enable two-factor
  authentication (e.g. when a server requires ``AuthenticationMethods
  pubkey,keyboard-interactive``). Thanks to ``@perryjrandall`` for the patch
  and to ``@nevins-b`` and Matt Robenolt for additional support.
- :bug:`502 major` Fix 'exec' requests in server mode to use ``get_string``
  instead of ``get_text`` to avoid ``UnicodeDecodeError`` on non-UTF-8 input.
  Thanks to Anselm Kruis for the patch & discussion.
- :bug:`401` Fix line number reporting in log output regarding invalid
  ``known_hosts`` line entries. Thanks to Dylan Thacker-Smith for catch &
  patch.
- :support:`525 backported` Update the vendored Windows API addon to a more
  recent edition. Also fixes :issue:`193`, :issue:`488`, :issue:`498`. Thanks
  to Jason Coombs.
- :release:`1.15.4 <2015-11-02>`
- :release:`1.14.3 <2015-11-02>`
- :release:`1.13.4 <2015-11-02>`
- :bug:`366` Fix `~paramiko.sftp_attr.SFTPAttributes` so its string
  representation doesn't raise exceptions on empty/initialized instances. Patch
  by Ulrich Petri.
- :bug:`359` Use correct attribute name when trying to use Python 3's
  ``int.bit_length`` method; prior to fix, the Python 2 custom fallback
  implementation was always used, even on Python 3. Thanks to Alex Gaynor.
- :support:`594 backported` Correct some post-Python3-port docstrings to
  specify ``bytes`` type instead of ``str``. Credit to ``@redixin``.
- :bug:`565` Don't explode with ``IndexError`` when reading private key files
  lacking an ``-----END <type> PRIVATE KEY-----`` footer. Patch courtesy of
  Prasanna Santhanam.
- :feature:`604` Add support for the ``aes192-ctr`` and ``aes192-cbc`` ciphers.
  Thanks to Michiel Tiller for noticing it was as easy as tweaking some key
  sizes :D
- :feature:`356` (also :issue:`596`, :issue:`365`, :issue:`341`, :issue:`164`,
  :issue:`581`, and a bunch of other duplicates besides) Add support for SHA-2
  based key exchange (kex) algorithm ``diffie-hellman-group-exchange-sha256``
  and (H)MAC algorithms ``hmac-sha2-256`` and ``hmac-sha2-512``.

  This change includes tweaks to debug-level logging regarding
  algorithm-selection handshakes; the old all-in-one log line is now multiple
  easier-to-read, printed-at-handshake-time log lines.

  Thanks to the many people who submitted patches for this functionality and/or
  assisted in testing those patches. That list includes but is not limited to,
  and in no particular order: Matthias Witte, Dag Wieers, Ash Berlin, Etienne
  Perot, Gert van Dijk, ``@GuyShaanan``, Aaron Bieber, ``@cyphase``, and Eric
  Brown.
- :release:`1.15.3 <2015-10-02>`
- :support:`554 backported` Fix inaccuracies in the docstring for the ECDSA key
  class. Thanks to Jared Hance for the patch.
- :support:`516 backported` Document `~paramiko.agent.AgentRequestHandler`.
  Thanks to ``@toejough`` for report & suggestions.
- :bug:`496 (1.15+)` Fix a handful of small but critical bugs in Paramiko's
  GSSAPI support (note: this includes switching from PyCrypo's Random to
  `os.urandom`). Thanks to Anselm Kruis for catch & patch.
- :bug:`491` (combines :issue:`62` and :issue:`439`) Implement timeout
  functionality to address hangs from dropped network connections and/or failed
  handshakes. Credit to ``@vazir`` and ``@dacut`` for the original patches and
  to Olle Lundberg for reimplementation.
- :bug:`490` Skip invalid/unparsable lines in ``known_hosts`` files, instead
  of raising `~paramiko.ssh_exception.SSHException`. This brings Paramiko's
  behavior more in line with OpenSSH, which silently ignores such input. Catch
  & patch courtesy of Martin Topholm.
- :bug:`404` Print details when displaying
  `~paramiko.ssh_exception.BadHostKeyException` objects (expected vs received
  data) instead of just "hey shit broke". Patch credit: Loic Dachary.
- :bug:`469` (also :issue:`488`, :issue:`461` and like a dozen others) Fix a
  typo introduced in the 1.15 release which broke WinPageant support. Thanks to
  everyone who submitted patches, and to Steve Cohen who was the lucky winner
  of the cherry-pick lottery.
- :bug:`353` (via :issue:`482`) Fix a bug introduced in the Python 3 port
  which caused ``OverFlowError`` (and other symptoms) in SFTP functionality.
  Thanks to ``@dboreham`` for leading the troubleshooting charge, and to
  Scott Maxwell for the final patch.
- :support:`582` Fix some old ``setup.py`` related helper code which was
  breaking ``bdist_dumb`` on Mac OS X. Thanks to Peter Odding for the patch.
- :bug:`22 major` Try harder to connect to multiple network families (e.g. IPv4
  vs IPv6) in case of connection issues; this helps with problems such as hosts
  which resolve both IPv4 and IPv6 addresses but are only listening on IPv4.
  Thanks to Dries Desmet for original report and Torsten Landschoff for the
  foundational patchset.
- :bug:`402` Check to see if an SSH agent is actually present before trying to
  forward it to the remote end. This replaces what was usually a useless
  ``TypeError`` with a human-readable
  `~paramiko.ssh_exception.AuthenticationException`. Credit to Ken Jordan for
  the fix and Yvan Marques for original report.
- :release:`1.15.2 <2014-12-19>`
- :release:`1.14.2 <2014-12-19>`
- :release:`1.13.3 <2014-12-19>`
- :bug:`413` (also :issue:`414`, :issue:`420`, :issue:`454`) Be significantly
  smarter about polling & timing behavior when running proxy commands, to avoid
  unnecessary (often 100%!) CPU usage. Major thanks to Jason Dunsmore for
  report & initial patchset and to Chris Adams & John Morrissey for followup
  improvements.
- :bug:`455` Tweak packet size handling to conform better to the OpenSSH RFCs;
  this helps address issues with interactive program cursors. Courtesy of Jeff
  Quast.
- :bug:`428` Fix an issue in `~paramiko.file.BufferedFile` (primarily used in
  the SFTP modules) concerning incorrect behavior by
  `~paramiko.file.BufferedFile.readlines` on files whose size exceeds the
  buffer size. Thanks to ``@achapp`` for catch & patch.
- :bug:`415` Fix ``ssh_config`` parsing to correctly interpret ``ProxyCommand
  none`` as the lack of a proxy command, instead of as a literal command string
  of ``"none"``. Thanks to Richard Spiers for the catch & Sean Johnson for the
  fix.
- :support:`431 backported` Replace handrolled ``ssh_config`` parsing code with
  use of the ``shlex`` module. Thanks to Yan Kalchevskiy.
- :support:`422 backported` Clean up some unused imports. Courtesy of Olle
  Lundberg.
- :support:`421 backported` Modernize threading calls to use newer API. Thanks
  to Olle Lundberg.
- :support:`419 backported` Modernize a bunch of the codebase internals to
  leverage decorators. Props to ``@beckjake`` for realizing we're no longer on
  Python 2.2 :D
- :bug:`266` Change numbering of `~paramiko.transport.Transport` channels to
  start at 0 instead of 1 for better compatibility with OpenSSH & certain
  server implementations which break on 1-indexed channels. Thanks to
  ``@egroeper`` for catch & patch.
- :bug:`459` Tighten up agent connection closure behavior to avoid spurious
  ``ResourceWarning`` display in some situations. Thanks to ``@tkrapp`` for the
  catch.
- :bug:`429` Server-level debug message logging was overlooked during the
  Python 3 compatibility update; Python 3 clients attempting to log SSH debug
  packets encountered type errors. This is now fixed. Thanks to ``@mjmaenpaa``
  for the catch.
- :bug:`320` Update our win_pageant module to be Python 3 compatible. Thanks to
  ``@sherbang`` and ``@adamkerz`` for the patches.
- :release:`1.15.1 <2014-09-22>`
- :bug:`399` SSH agent forwarding (potentially other functionality as
  well) would hang due to incorrect values passed into the new window size
  arguments for `~paramiko.transport.Transport` (thanks to a botched merge).
  This has been corrected. Thanks to Dylan Thacker-Smith for the report &
  patch.
- :feature:`167` Add `~paramiko.config.SSHConfig.get_hostnames` for easier
  introspection of a loaded SSH config file or object. Courtesy of Søren
  Løvborg.
- :release:`1.15.0 <2014-09-18>`
- :support:`393` Replace internal use of PyCrypto's ``SHA.new`` with the
  stdlib's ``hashlib.sha1``. Thanks to Alex Gaynor.
- :feature:`267` (also :issue:`250`, :issue:`241`, :issue:`228`) Add GSS-API /
  SSPI (e.g. Kerberos) key exchange and authentication support
  (:ref:`installation docs here <gssapi>`). Mega thanks to Sebastian Deiß, with
  assist by Torsten Landschoff.

  .. note::
      Unix users should be aware that the ``python-gssapi`` library (a
      requirement for using this functionality) only appears to support
      Python 2.7 and up at this time.

- :bug:`346 major` Fix an issue in private key files' encryption salts that
  could cause tracebacks and file corruption if keys were re-encrypted. Credit
  to Xavier Nunn.
- :feature:`362` Allow users to control the SSH banner timeout. Thanks to Cory
  Benfield.
- :feature:`372` Update default window & packet sizes to more closely adhere to
  the pertinent RFC; also expose these settings in the public API so they may
  be overridden by client code. This should address some general speed issues
  such as :issue:`175`. Big thanks to Olle Lundberg for the update.
- :bug:`373 major` Attempt to fix a handful of issues (such as :issue:`354`)
  related to infinite loops and threading deadlocks. Thanks to Olle Lundberg as
  well as a handful of community members who provided advice & feedback via
  IRC.
- :support:`374` (also :issue:`375`) Old code cleanup courtesy of Olle
  Lundberg.
- :support:`377` Factor `~paramiko.channel.Channel` openness sanity check into
  a decorator. Thanks to Olle Lundberg for original patch.
- :bug:`298 major` Don't perform point validation on ECDSA keys in
  ``known_hosts`` files, since a) this can cause significant slowdown when such
  keys exist, and b) ``known_hosts`` files are implicitly trustworthy. Thanks
  to Kieran Spear for catch & patch.

  .. note::
    This change bumps up the version requirement for the ``ecdsa`` library to
    ``0.11``.

- :bug:`234 major` Lower logging levels for a few overly-noisy log messages
  about secure channels. Thanks to David Pursehouse for noticing & contributing
  the fix.
- :feature:`218` Add support for ECDSA private keys on the client side. Thanks
  to ``@aszlig`` for the patch.
- :bug:`335 major` Fix ECDSA key generation (generation of brand new ECDSA keys
  was broken previously). Thanks to ``@solarw`` for catch & patch.
- :feature:`184` Support quoted values in SSH config file parsing. Credit to
  Yan Kalchevskiy.
- :feature:`131` Add a `~paramiko.sftp_client.SFTPClient.listdir_iter` method
  to `~paramiko.sftp_client.SFTPClient` allowing for more efficient,
  async/generator based file listings. Thanks to John Begeman.
- :support:`378 backported` Minor code cleanup in the SSH config module
  courtesy of Olle Lundberg.
- :support:`249 backported` Consolidate version information into one spot.
  Thanks to Gabi Davar for the reminder.
- :release:`1.14.1 <2014-08-25>`
- :release:`1.13.2 <2014-08-25>`
- :bug:`376` Be less aggressive about expanding variables in ``ssh_config``
  files, which results in a speedup of SSH config parsing. Credit to Olle
  Lundberg.
- :support:`324 backported` A bevvy of documentation typo fixes, courtesy of Roy
  Wellington.
- :bug:`312` `paramiko.transport.Transport` had a bug in its ``__repr__`` which
  surfaces during errors encountered within its ``__init__``, causing
  problematic tracebacks in such situations. Thanks to Simon Percivall for
  catch & patch.
- :bug:`272` Fix a bug where ``known_hosts`` parsing hashed the input hostname
  as well as the hostnames from the ``known_hosts`` file, on every comparison.
  Thanks to ``@sigmunau`` for final patch and ``@ostacey`` for the original
  report.
- :bug:`239` Add Windows-style CRLF support to SSH config file parsing. Props
  to Christopher Swenson.
- :support:`229 backported` Fix a couple of incorrectly-copied docstrings' ``..
  versionadded::`` RST directives. Thanks to Aarni Koskela for the catch.
- :support:`169 backported` Minor refactor of
  `paramiko.sftp_client.SFTPClient.put` thanks to Abhinav Upadhyay.
- :bug:`285` (also :issue:`352`) Update our Python 3 ``b()`` compatibility shim
  to handle ``buffer`` objects correctly; this fixes a frequently reported
  issue affecting many users, including users of the ``bzr`` software suite.
  Thanks to ``@basictheprogram`` for the initial report, Jelmer Vernooij for
  the fix and Andrew Starr-Bochicchio & Jeremy T. Bouse (among others) for
  discussion & feedback.
- :support:`371` Add Travis support & docs update for Python 3.4. Thanks to
  Olle Lundberg.
- :release:`1.14.0 <2014-05-07>`
- :release:`1.13.1 <2014-05-07>`
- :release:`1.12.4 <2014-05-07>`
- :release:`1.11.6 <2014-05-07>`
- :bug:`-` `paramiko.file.BufferedFile.read` incorrectly returned text strings
  after the Python 3 migration, despite bytes being more appropriate for file
  contents (which may be binary or of an unknown encoding.) This has been
  addressed.

  .. note::
      `paramiko.file.BufferedFile.readline` continues to return strings, not
      bytes, as "lines" only make sense for textual data. It assumes UTF-8 by
      default.

  This should fix `this issue raised on the Obnam mailing list
  <http://comments.gmane.org/gmane.comp.sysutils.backup.obnam/252>`_.  Thanks
  to Antoine Brenner for the patch.
- :bug:`-` Added self.args for exception classes. Used for unpickling. Related
  to (`Fabric #986 <https://github.com/fabric/fabric/issues/986>`_, `Fabric
  #714 <https://github.com/fabric/fabric/issues/714>`_). Thanks to Alex
  Plugaru.
- :bug:`-` Fix logging error in sftp_client for filenames containing the '%'
  character. Thanks to Antoine Brenner.
- :bug:`308` Fix regression in dsskey.py that caused sporadic signature
  verification failures. Thanks to Chris Rose.
- :support:`299` Use deterministic signatures for ECDSA keys for improved
  security. Thanks to Alex Gaynor.
- :support:`297` Replace PyCrypto's ``Random`` with `os.urandom` for improved
  speed and security. Thanks again to Alex.
- :support:`295` Swap out a bunch of PyCrypto hash functions with use of
  `hashlib`. Thanks to Alex Gaynor.
- :support:`290` (also :issue:`292`) Add support for building universal
  (Python 2+3 compatible) wheel files during the release process. Courtesy of
  Alex Gaynor.
- :support:`284` Add Python language trove identifiers to ``setup.py``. Thanks
  to Alex Gaynor for catch & patch.
- :bug:`235` Improve string type testing in a handful of spots (e.g. ``s/if
  type(x) is str/if isinstance(x, basestring)/g``.) Thanks to ``@ksamuel`` for
  the report.
- :release:`1.13.0 <2014-03-13>`
- :release:`1.12.3 <2014-03-13>`
- :release:`1.11.5 <2014-03-13>`
- :release:`1.10.7 <2014-03-13>`
- :feature:`16` **Python 3 support!** Our test suite passes under Python 3, and
  it (& Fabric's test suite) continues to pass under Python 2. **Python 2.5 is
  no longer supported with this change!**

  The merged code was built on many contributors' efforts, both code &
  feedback. In no particular order, we thank Daniel Goertzen, Ivan Kolodyazhny,
  Tomi Pieviläinen, Jason R. Coombs, Jan N. Schulze, ``@Lazik``, Dorian Pula,
  Scott Maxwell, Tshepang Lekhonkhobe, Aaron Meurer, and Dave Halter.
- :support:`256 backported` Convert API documentation to Sphinx, yielding a new
  API docs website to replace the old Epydoc one. Thanks to Olle Lundberg for
  the initial conversion work.
- :bug:`-` Use constant-time hash comparison operations where possible, to
  protect against `timing-based attacks
  <http://codahale.com/a-lesson-in-timing-attacks/>`_. Thanks to Alex Gaynor
  for the patch.
- :release:`1.12.2 <2014-02-14>`
- :release:`1.11.4 <2014-02-14>`
- :release:`1.10.6 <2014-02-14>`
- :feature:`58` Allow client code to access the stored SSH server banner via
  `Transport.get_banner <paramiko.transport.Transport.get_banner>`. Thanks to
  ``@Jhoanor`` for the patch.
- :bug:`252` (`Fabric #1020 <https://github.com/fabric/fabric/issues/1020>`_)
  Enhanced the implementation of ``ProxyCommand`` to avoid a deadlock/hang
  condition that frequently occurs at ``Transport`` shutdown time. Thanks to
  Mateusz Kobos, Matthijs van der Vleuten and Guillaume Zitta for the original
  reports and to Marius Gedminas for helping test nontrivial use cases.
- :bug:`268` Fix some missed renames of ``ProxyCommand`` related error classes.
  Thanks to Marius Gedminas for catch & patch.
- :bug:`34` (PR :issue:`35`) Fix SFTP prefetching incompatibility with some
  SFTP servers regarding request/response ordering. Thanks to Richard
  Kettlewell.
- :bug:`193` (and its attentant PRs :issue:`230` & :issue:`253`) Fix SSH agent
  problems present on Windows. Thanks to David Hobbs for initial report and to
  Aarni Koskela & Olle Lundberg for the patches.
- :release:`1.12.1 <2014-01-08>`
- :release:`1.11.3 <2014-01-08>`
- :release:`1.10.5 <2014-01-08>`
- :bug:`225 (1.12+)` Note ecdsa requirement in README. Thanks to Amaury
  Rodriguez for the catch.
- :bug:`176` Fix AttributeError bugs in known_hosts file (re)loading. Thanks
  to Nathan Scowcroft for the patch & Martin Blumenstingl for the initial test
  case.
- :release:`1.12.0 <2013-09-27>`
- :release:`1.11.2 <2013-09-27>`
- :release:`1.10.4 <2013-09-27>`
- :feature:`152` Add tentative support for ECDSA keys. **This adds the ecdsa
  module as a new dependency of Paramiko.** The module is available at
  `warner/python-ecdsa on Github <https://github.com/warner/python-ecdsa>`_ and
  `ecdsa on PyPI <https://pypi.python.org/pypi/ecdsa>`_.

    * Note that you might still run into problems with key negotiation --
      Paramiko picks the first key that the server offers, which might not be
      what you have in your known_hosts file.
    * Mega thanks to Ethan Glasser-Camp for the patch.

- :feature:`136` Add server-side support for the SSH protocol's 'env' command.
  Thanks to Benjamin Pollack for the patch.
- :bug:`156 (1.11+)` Fix potential deadlock condition when using Channel
  objects as sockets (e.g. when using SSH gatewaying). Thanks to Steven Noonan
  and Frank Arnold for catch & patch.
- :bug:`179` Fix a missing variable causing errors when an ssh_config file has
  a non-default AddressFamily set. Thanks to Ed Marshall & Tomaz Muraus for
  catch & patch.
- :bug:`200` Fix an exception-causing typo in ``demo_simple.py``. Thanks to Alex
  Buchanan for catch & Dave Foster for patch.
- :bug:`199` Typo fix in the license header cross-project. Thanks to Armin
  Ronacher for catch & patch.
- :release:`1.11.1 <2013-09-20>`
- :release:`1.10.3 <2013-09-20>`
- :bug:`162` Clean up HMAC module import to avoid deadlocks in certain uses of
  SSHClient. Thanks to Gernot Hillier for the catch & suggested fix.
- :bug:`36` Fix the port-forwarding demo to avoid file descriptor errors.
  Thanks to Jonathan Halcrow for catch & patch.
- :bug:`168` Update config handling to properly handle multiple 'localforward'
  and 'remoteforward' keys. Thanks to Emre Yılmaz for the patch.
- :release:`1.11.0 <2013-07-26>`
- :release:`1.10.2 <2013-07-26>`
- :bug:`98 major` On Windows, when interacting with the PuTTY PAgeant, Paramiko
  now creates the shared memory map with explicit Security Attributes of the
  user, which is the same technique employed by the canonical PuTTY library to
  avoid permissions issues when Paramiko is running under a different UAC
  context than the PuTTY Ageant process. Thanks to Jason R. Coombs for the
  patch.
- :support:`100` Remove use of PyWin32 in ``win_pageant`` module. Module was
  already dependent on ctypes for constructing appropriate structures and had
  ctypes implementations of all functionality. Thanks to Jason R. Coombs for
  the patch.
- :bug:`87 major` Ensure updates to ``known_hosts`` files account for any
  updates to said files after Paramiko initially read them. (Includes related
  fix to guard against duplicate entries during subsequent ``known_hosts``
  loads.) Thanks to ``@sunweaver`` for the contribution.
- :bug:`153` (also :issue:`67`) Warn on parse failure when reading known_hosts
  file.  Thanks to ``@glasserc`` for patch.
- :bug:`146` Indentation fixes for readability. Thanks to Abhinav Upadhyay for
  catch & patch.
- :release:`1.10.1 <2013-04-05>`
- :bug:`142` (`Fabric #811 <https://github.com/fabric/fabric/issues/811>`_)
  SFTP put of empty file will still return the attributes of the put file.
  Thanks to Jason R. Coombs for the patch.
- :bug:`154` (`Fabric #876 <https://github.com/fabric/fabric/issues/876>`_)
  Forwarded SSH agent connections left stale local pipes lying around, which
  could cause local (and sometimes remote or network) resource starvation when
  running many agent-using remote commands. Thanks to Kevin Tegtmeier for catch
  & patch.
- :release:`1.10.0 <2013-03-01>`
- :feature:`66` Batch SFTP writes to help speed up file transfers. Thanks to
  Olle Lundberg for the patch.
- :bug:`133 major` Fix handling of window-change events to be on-spec and not
  attempt to wait for a response from the remote sshd; this fixes problems with
  less common targets such as some Cisco devices. Thanks to Phillip Heller for
  catch & patch.
- :feature:`93` Overhaul SSH config parsing to be in line with ``man
  ssh_config`` (& the behavior of ``ssh`` itself), including addition of parameter
  expansion within config values. Thanks to Olle Lundberg for the patch.
- :feature:`110` Honor SSH config ``AddressFamily`` setting when looking up
  local host's FQDN. Thanks to John Hensley for the patch.
- :feature:`128` Defer FQDN resolution until needed, when parsing SSH config
  files.  Thanks to Parantapa Bhattacharya for catch & patch.
- :bug:`102 major` Forego random padding for packets when running under
  ``*-ctr`` ciphers.  This corrects some slowdowns on platforms where random
  byte generation is inefficient (e.g. Windows). Thanks to  ``@warthog618`` for
  catch & patch, and Michael van der Kolff for code/technique review.
- :feature:`127` Turn ``SFTPFile`` into a context manager. Thanks to Michael
  Williamson for the patch.
- :feature:`116` Limit ``Message.get_bytes`` to an upper bound of 1MB to protect
  against potential DoS vectors. Thanks to ``@mvschaik`` for catch & patch.
- :feature:`115` Add convenience ``get_pty`` kwarg to ``Client.exec_command`` so
  users not manually controlling a channel object can still toggle PTY
  creation. Thanks to Michael van der Kolff for the patch.
- :feature:`71` Add ``SFTPClient.putfo`` and ``.getfo`` methods to allow direct
  uploading/downloading of file-like objects. Thanks to Eric Buehl for the
  patch.
- :feature:`113` Add ``timeout`` parameter to ``SSHClient.exec_command`` for
  easier setting of the command's internal channel object's timeout. Thanks to
  Cernov Vladimir for the patch.
- :support:`94` Remove duplication of SSH port constant. Thanks to Olle
  Lundberg for the catch.
- :feature:`80` Expose the internal "is closed" property of the file transfer
  class ``BufferedFile`` as ``.closed``, better conforming to Python's file
  interface.  Thanks to ``@smunaut`` and James Hiscock for catch & patch.
