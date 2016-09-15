===================================
Frequently Asked/Answered Questions
===================================

Which version should I use? I see multiple active releases.
===========================================================

Please see :ref:`the installation docs <release-lines>` which have an explicit
section about this topic.

Paramiko doesn't work with my Cisco, Windows or other non-Unix system!
======================================================================

In an ideal world, the developers would love to support every possible target
system. Unfortunately, volunteer development time and access to non-mainstream
platforms are limited, meaning that we can only fully support standard OpenSSH
implementations such as those found on the average Linux distribution (as well
as on Mac OS X and \*BSD.)

Because of this, **we typically close bug reports for nonstandard SSH
implementations or host systems**.

However, **closed does not imply locked** - affected users can still post
comments on such tickets - and **we will always consider actual patch
submissions for these issues**, provided they can get +1s from similarly
affected users and are proven to not break existing functionality.

I'm having strange issues with my code hanging at shutdown!
===========================================================

Make sure you explicitly ``.close()`` your connection objects (usually
``SSHClient``) if you're having any sort of hang/freeze at shutdown time!

Doing so isn't strictly necessary 100% of the time, but it is almost always the
right solution if you run into the various corner cases that cause race
conditions, etc.
