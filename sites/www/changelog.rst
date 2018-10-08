=========
Changelog
=========

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
- :support:`1292 backported` Backport changes from :issue:`979` (added in
  Paramiko 2.3) to Paramiko 2.0-2.2, using duck-typing to preserve backwards
  compatibility. This allows these older versions to use newer Cryptography
  sign/verify APIs when available, without requiring them (as is the case with
  Paramiko 2.3+).

  Practically speaking, this change prevents spamming of
  ``CryptographyDeprecationWarning`` notices which pop up in the above scenario
  (older Paramiko, newer Cryptography).

  .. note::
    This is a no-op for Paramiko 2.3+, which have required newer Cryptography
    releases since they were released.

- :support:`1291 backported` Backport pytest support and application of the
  ``black`` code formatter (both of which previously only existed in the 2.4
  branch and above) to everything 2.0 and newer. This makes back/forward
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
- :bug:`490` Skip invalid/unparseable lines in ``known_hosts`` files, instead
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
