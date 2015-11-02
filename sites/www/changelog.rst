=========
Changelog
=========

* :bug:`366` Fix `~paramiko.sftp_attributes.SFTPAttributes` so its string
  representation doesn't raise exceptions on empty/initialized instances. Patch
  by Ulrich Petri.
* :bug:`359` Use correct attribute name when trying to use Python 3's
  ``int.bit_length`` method; prior to fix, the Python 2 custom fallback
  implementation was always used, even on Python 3. Thanks to Alex Gaynor.
* :support:`594 backported` Correct some post-Python3-port docstrings to
  specify ``bytes`` type instead of ``str``. Credit to ``@redixin``.
* :bug:`565` Don't explode with ``IndexError`` when reading private key files
  lacking an ``-----END <type> PRIVATE KEY-----`` footer. Patch courtesy of
  Prasanna Santhanam.
* :release:`1.13.3 <2014-12-19>`
* :bug:`413` (also :issue:`414`, :issue:`420`, :issue:`454`) Be significantly
  smarter about polling & timing behavior when running proxy commands, to avoid
  unnecessary (often 100%!) CPU usage. Major thanks to Jason Dunsmore for
  report & initial patchset and to Chris Adams & John Morrissey for followup
  improvements.
* :bug:`428` Fix an issue in `~paramiko.file.BufferedFile` (primarily used in
  the SFTP modules) concerning incorrect behavior by
  `~paramiko.file.BufferedFile.readlines` on files whose size exceeds the
  buffer size. Thanks to ``@achapp`` for catch & patch.
* :support:`422 backported` Clean up some unused imports. Courtesy of Olle
  Lundberg.
* :bug:`266` Change numbering of `~paramiko.transport.Transport` channels to
  start at 0 instead of 1 for better compatibility with OpenSSH & certain
  server implementations which break on 1-indexed channels. Thanks to
  ``@egroeper`` for catch & patch.
* :bug:`459` Tighten up agent connection closure behavior to avoid spurious
  ``ResourceWarning`` display in some situations. Thanks to ``@tkrapp`` for the
  catch.
* :bug:`429` Server-level debug message logging was overlooked during the
  Python 3 compatibility update; Python 3 clients attempting to log SSH debug
  packets encountered type errors. This is now fixed. Thanks to ``@mjmaenpaa``
  for the catch.
* :bug:`320` Update our win_pageant module to be Python 3 compatible. Thanks to
  ``@sherbang`` and ``@adamkerz`` for the patches.
* :support:`378 backported` Minor code cleanup in the SSH config module
  courtesy of Olle Lundberg.
* :support:`249 backported` Consolidate version information into one spot.
  Thanks to Gabi Davar for the reminder.
* :release:`1.13.2 <2014-08-25>`
* :bug:`376` Be less aggressive about expanding variables in ``ssh_config``
  files, which results in a speedup of SSH config parsing. Credit to Olle
  Lundberg.
* :support:`324 backported` A bevvy of documentation typo fixes, courtesy of Roy
  Wellington.
* :bug:`312` `paramiko.transport.Transport` had a bug in its ``__repr__`` which
  surfaces during errors encountered within its ``__init__``, causing
  problematic tracebacks in such situations. Thanks to Simon Percivall for
  catch & patch.
* :bug:`272` Fix a bug where ``known_hosts`` parsing hashed the input hostname
  as well as the hostnames from the ``known_hosts`` file, on every comparison.
  Thanks to ``@sigmunau`` for final patch and ``@ostacey`` for the original
  report.
* :bug:`239` Add Windows-style CRLF support to SSH config file parsing. Props
  to Christopher Swenson.
* :support:`229 backported` Fix a couple of incorrectly-copied docstrings' ``..
  versionadded::`` RST directives. Thanks to Aarni Koskela for the catch.
* :support:`169 backported` Minor refactor of
  `paramiko.sftp_client.SFTPClient.put` thanks to Abhinav Upadhyay.
* :bug:`285` (also :issue:`352`) Update our Python 3 ``b()`` compatibility shim
  to handle ``buffer`` objects correctly; this fixes a frequently reported
  issue affecting many users, including users of the ``bzr`` software suite.
  Thanks to ``@basictheprogram`` for the initial report, Jelmer Vernooij for
  the fix and Andrew Starr-Bochicchio & Jeremy T. Bouse (among others) for
  discussion & feedback.
* :release:`1.13.1 <2014-05-07>`
* :release:`1.12.4 <2014-05-07>`
* :release:`1.11.6 <2014-05-07>`
* :bug:`-` `paramiko.file.BufferedFile.read` incorrectly returned text strings
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
* :bug:`-` Added self.args for exception classes. Used for unpickling. Related
  to (`Fabric #986 <https://github.com/fabric/fabric/issues/986>`_, `Fabric
  #714 <https://github.com/fabric/fabric/issues/714>`_). Thanks to Alex
  Plugaru.
* :bug:`-` Fix logging error in sftp_client for filenames containing the '%'
  character. Thanks to Antoine Brenner.
* :bug:`308` Fix regression in dsskey.py that caused sporadic signature 
  verification failures. Thanks to Chris Rose.
* :support:`290` (also :issue:`292`) Add support for building universal
  (Python 2+3 compatible) wheel files during the release process. Courtesy of
  Alex Gaynor.
* :support:`284` Add Python language trove identifiers to ``setup.py``. Thanks
  to Alex Gaynor for catch & patch.
* :bug:`235` Improve string type testing in a handful of spots (e.g. ``s/if
  type(x) is str/if isinstance(x, basestring)/g``.) Thanks to ``@ksamuel`` for
  the report.
* :release:`1.13.0 <2014-03-13>`
* :release:`1.12.3 <2014-03-13>`
* :release:`1.11.5 <2014-03-13>`
* :release:`1.10.7 <2014-03-13>`
* :feature:`16` **Python 3 support!** Our test suite passes under Python 3, and
  it (& Fabric's test suite) continues to pass under Python 2.
  
  The merged code was built on many contributors' efforts, both code &
  feedback. In no particular order, we thank Daniel Goertzen, Ivan Kolodyazhny,
  Tomi Pieviläinen, Jason R. Coombs, Jan N. Schulze, ``@Lazik``, Dorian Pula,
  Scott Maxwell, Tshepang Lekhonkhobe, Aaron Meurer, and Dave Halter.
* :support:`256 backported` Convert API documentation to Sphinx, yielding a new
  API docs website to replace the old Epydoc one. Thanks to Olle Lundberg for
  the initial conversion work.
* :bug:`-` Use constant-time hash comparison operations where possible, to
  protect against `timing-based attacks
  <http://codahale.com/a-lesson-in-timing-attacks/>`_. Thanks to Alex Gaynor
  for the patch.
* :release:`1.12.2 <2014-02-14>`
* :release:`1.11.4 <2014-02-14>`
* :release:`1.10.6 <2014-02-14>`
* :feature:`58` Allow client code to access the stored SSH server banner via
  `Transport.get_banner <paramiko.transport.Transport.get_banner>`. Thanks to
  ``@Jhoanor`` for the patch.
* :bug:`252` (`Fabric #1020 <https://github.com/fabric/fabric/issues/1020>`_)
  Enhanced the implementation of ``ProxyCommand`` to avoid a deadlock/hang
  condition that frequently occurs at ``Transport`` shutdown time. Thanks to
  Mateusz Kobos, Matthijs van der Vleuten and Guillaume Zitta for the original
  reports and to Marius Gedminas for helping test nontrivial use cases.
* :bug:`268` Fix some missed renames of ``ProxyCommand`` related error classes.
  Thanks to Marius Gedminas for catch & patch.
* :bug:`34` (PR :issue:`35`) Fix SFTP prefetching incompatibility with some
  SFTP servers regarding request/response ordering. Thanks to Richard
  Kettlewell.
* :bug:`193` (and its attentant PRs :issue:`230` & :issue:`253`) Fix SSH agent
  problems present on Windows. Thanks to David Hobbs for initial report and to
  Aarni Koskela & Olle Lundberg for the patches.
* :release:`1.12.1 <2014-01-08>`
* :release:`1.11.3 <2014-01-08>`
* :release:`1.10.5 <2014-01-08>`
* :bug:`225 (1.12+)` Note ecdsa requirement in README. Thanks to Amaury
  Rodriguez for the catch.
* :bug:`176` Fix AttributeError bugs in known_hosts file (re)loading. Thanks
  to Nathan Scowcroft for the patch & Martin Blumenstingl for the initial test
  case.
* :release:`1.12.0 <2013-09-27>`
* :release:`1.11.2 <2013-09-27>`
* :release:`1.10.4 <2013-09-27>`
* :feature:`152` Add tentative support for ECDSA keys. **This adds the ecdsa
  module as a new dependency of Paramiko.** The module is available at
  `warner/python-ecdsa on Github <https://github.com/warner/python-ecdsa>`_ and
  `ecdsa on PyPI <https://pypi.python.org/pypi/ecdsa>`_.

    * Note that you might still run into problems with key negotiation --
      Paramiko picks the first key that the server offers, which might not be
      what you have in your known_hosts file.
    * Mega thanks to Ethan Glasser-Camp for the patch.

* :feature:`136` Add server-side support for the SSH protocol's 'env' command.
  Thanks to Benjamin Pollack for the patch.
* :bug:`156 (1.11+)` Fix potential deadlock condition when using Channel
  objects as sockets (e.g. when using SSH gatewaying). Thanks to Steven Noonan
  and Frank Arnold for catch & patch.
* :bug:`179` Fix a missing variable causing errors when an ssh_config file has
  a non-default AddressFamily set. Thanks to Ed Marshall & Tomaz Muraus for
  catch & patch.
* :bug:`200` Fix an exception-causing typo in ``demo_simple.py``. Thanks to Alex
  Buchanan for catch & Dave Foster for patch.
* :bug:`199` Typo fix in the license header cross-project. Thanks to Armin
  Ronacher for catch & patch.
* :release:`1.11.1 <2013-09-20>`
* :release:`1.10.3 <2013-09-20>`
* :bug:`162` Clean up HMAC module import to avoid deadlocks in certain uses of
  SSHClient. Thanks to Gernot Hillier for the catch & suggested fix.
* :bug:`36` Fix the port-forwarding demo to avoid file descriptor errors.
  Thanks to Jonathan Halcrow for catch & patch.
* :bug:`168` Update config handling to properly handle multiple 'localforward'
  and 'remoteforward' keys. Thanks to Emre Yılmaz for the patch.
* :release:`1.11.0 <2013-07-26>`
* :release:`1.10.2 <2013-07-26>`
* :bug:`98 major` On Windows, when interacting with the PuTTY PAgeant, Paramiko
  now creates the shared memory map with explicit Security Attributes of the
  user, which is the same technique employed by the canonical PuTTY library to
  avoid permissions issues when Paramiko is running under a different UAC
  context than the PuTTY Ageant process. Thanks to Jason R. Coombs for the
  patch.
* :support:`100` Remove use of PyWin32 in ``win_pageant`` module. Module was
  already dependent on ctypes for constructing appropriate structures and had
  ctypes implementations of all functionality. Thanks to Jason R. Coombs for
  the patch.
* :bug:`87 major` Ensure updates to ``known_hosts`` files account for any
  updates to said files after Paramiko initially read them. (Includes related
  fix to guard against duplicate entries during subsequent ``known_hosts``
  loads.) Thanks to ``@sunweaver`` for the contribution.
* :bug:`153` (also :issue:`67`) Warn on parse failure when reading known_hosts
  file.  Thanks to ``@glasserc`` for patch.
* :bug:`146` Indentation fixes for readability. Thanks to Abhinav Upadhyay for
  catch & patch.
* :release:`1.10.1 <2013-04-05>`
* :bug:`142` (`Fabric #811 <https://github.com/fabric/fabric/issues/811>`_)
  SFTP put of empty file will still return the attributes of the put file.
  Thanks to Jason R. Coombs for the patch.
* :bug:`154` (`Fabric #876 <https://github.com/fabric/fabric/issues/876>`_)
  Forwarded SSH agent connections left stale local pipes lying around, which
  could cause local (and sometimes remote or network) resource starvation when
  running many agent-using remote commands. Thanks to Kevin Tegtmeier for catch
  & patch.
* :release:`1.10.0 <2013-03-01>`
* :feature:`66` Batch SFTP writes to help speed up file transfers. Thanks to
  Olle Lundberg for the patch.
* :bug:`133 major` Fix handling of window-change events to be on-spec and not
  attempt to wait for a response from the remote sshd; this fixes problems with
  less common targets such as some Cisco devices. Thanks to Phillip Heller for
  catch & patch.
* :feature:`93` Overhaul SSH config parsing to be in line with ``man
  ssh_config`` (& the behavior of ``ssh`` itself), including addition of parameter
  expansion within config values. Thanks to Olle Lundberg for the patch.
* :feature:`110` Honor SSH config ``AddressFamily`` setting when looking up
  local host's FQDN. Thanks to John Hensley for the patch.
* :feature:`128` Defer FQDN resolution until needed, when parsing SSH config
  files.  Thanks to Parantapa Bhattacharya for catch & patch.
* :bug:`102 major` Forego random padding for packets when running under
  ``*-ctr`` ciphers.  This corrects some slowdowns on platforms where random
  byte generation is inefficient (e.g. Windows). Thanks to  ``@warthog618`` for
  catch & patch, and Michael van der Kolff for code/technique review.
* :feature:`127` Turn ``SFTPFile`` into a context manager. Thanks to Michael
  Williamson for the patch.
* :feature:`116` Limit ``Message.get_bytes`` to an upper bound of 1MB to protect
  against potential DoS vectors. Thanks to ``@mvschaik`` for catch & patch.
* :feature:`115` Add convenience ``get_pty`` kwarg to ``Client.exec_command`` so
  users not manually controlling a channel object can still toggle PTY
  creation. Thanks to Michael van der Kolff for the patch.
* :feature:`71` Add ``SFTPClient.putfo`` and ``.getfo`` methods to allow direct
  uploading/downloading of file-like objects. Thanks to Eric Buehl for the
  patch.
* :feature:`113` Add ``timeout`` parameter to ``SSHClient.exec_command`` for
  easier setting of the command's internal channel object's timeout. Thanks to
  Cernov Vladimir for the patch.
* :support:`94` Remove duplication of SSH port constant. Thanks to Olle
  Lundberg for the catch.
* :feature:`80` Expose the internal "is closed" property of the file transfer
  class ``BufferedFile`` as ``.closed``, better conforming to Python's file
  interface.  Thanks to ``@smunaut`` and James Hiscock for catch & patch.
