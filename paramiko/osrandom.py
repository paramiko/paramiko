#!/usr/bin/python
# -*- coding: ascii -*-
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys

# Detect an OS random number source
osrandom_source = None

# Try os.urandom
if osrandom_source is None:
    try:
        from os import urandom
        osrandom_source = "os.urandom"
    except ImportError:
        pass

# Try winrandom
if osrandom_source is None:
    try:
        from Crypto.Util import winrandom
        osrandom_source = "winrandom"
    except ImportError:
        pass

# Try /dev/urandom
if osrandom_source is None:
    try:
        _dev_urandom = open("/dev/urandom", "rb", 0)
        def urandom(bytes):
            return _def_urandom.read(bytes)
        osrandom_source = "/dev/urandom"
    except (OSError, IOError):
        pass

# Give up
if osrandom_source is None:
    raise ImportError("Cannot find OS entropy source")

class BaseOSRandomPool(object):
    def __init__(self, numbytes=160, cipher=None, hash=None):
        pass

    def stir(self, s=''):
        # According to "Cryptanalysis of the Random Number Generator of the
        # Windows Operating System", by Leo Dorrendorf and Zvi Gutterman
        # and Benny Pinkas <http://eprint.iacr.org/2007/419>,
        # CryptGenRandom only updates its internal state using kernel-provided
        # random data every 128KiB of output.
        if osrandom_source == 'winrandom' or sys.platform == 'win32':
            self.get_bytes(128*1024)    # discard 128 KiB of output

    def randomize(self, N=0):
        self.stir()

    def add_event(self, s=None):
        pass

class WinrandomOSRandomPool(BaseOSRandomPool):
    def __init__(self, numbytes=160, cipher=None, hash=None):
        self._wr = winrandom.new()
        self.get_bytes = self._wr.get_bytes
        self.randomize()

class UrandomOSRandomPool(BaseOSRandomPool):
    def __init__(self, numbytes=160, cipher=None, hash=None):
        self.get_bytes = urandom
        self.randomize()

if osrandom_source in ("/dev/urandom", "os.urandom"):
    OSRandomPool = UrandomOSRandomPool
elif osrandom_source == "winrandom":
    OSRandomPool = WinrandomOSRandomPool
else:
    raise AssertionError("Unrecognized osrandom_source %r" % (osrandom_source,))

# vim:set ts=4 sw=4 sts=4 expandtab:
