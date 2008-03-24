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

##
## Find potential random number sources
##

# Try to open /dev/urandom now so that paramiko will be able to access
# it even if os.chroot() is invoked later.
try:
    _dev_urandom = open("/dev/urandom", "rb", 0)
except EnvironmentError:
    _dev_urandom = None

# Try to import the "winrandom" module
try:
    from Crypto.Util import winrandom
except ImportError:
    winrandom = None

# Lastly, try to get the plain "RandomPool"
# (sometimes windows doesn't even have winrandom!)
try:
    from Crypto.Util.randpool import RandomPool
except ImportError:
    RandomPool = None


##
## Define RandomPool classes
##

def _workaround_windows_cryptgenrandom_bug(self):
    # According to "Cryptanalysis of the Random Number Generator of the
    # Windows Operating System", by Leo Dorrendorf and Zvi Gutterman
    # and Benny Pinkas <http://eprint.iacr.org/2007/419>,
    # CryptGenRandom only updates its internal state using kernel-provided
    # random data every 128KiB of output.
    self.get_bytes(128*1024)    # discard 128 KiB of output


class BaseOSRandomPool(object):
    def __init__(self, numbytes=160, cipher=None, hash=None):
        pass

    def stir(self, s=''):
        pass

    def randomize(self, N=0):
        self.stir()

    def add_event(self, s=None):
        pass


class WinRandomPool(BaseOSRandomPool):
    """RandomPool that uses the C{winrandom} module for input"""
    def __init__(self, numbytes=160, cipher=None, hash=None):
        self._wr = winrandom.new()
        self.get_bytes = self._wr.get_bytes
        self.randomize()

    def stir(self, s=''):
        _workaround_windows_cryptgenrandom_bug(self)


class DevUrandomPool(BaseOSRandomPool):
    """RandomPool that uses the C{/dev/urandom} special device node for input"""
    def __init__(self, numbytes=160, cipher=None, hash=None):
        self.randomize()

    def get_bytes(self, n):
        bytes = ""
        while len(bytes) < n:
            bytes += _dev_urandom.read(n - len(bytes))
        return bytes


class FallbackRandomPool (BaseOSRandomPool):
    def __init__(self):
        self._wr = RandomPool()
        self.randomize()

    def get_bytes(self, n):
        return self._wr.get_bytes(n)


##
## Detect default random number source
##
osrandom_source = None

# Try /dev/urandom
if osrandom_source is None and _dev_urandom is not None:
    osrandom_source = "/dev/urandom"
    DefaultRandomPoolClass = DevUrandomPool

# Try winrandom
if osrandom_source is None and winrandom is not None:
    osrandom_source = "winrandom"
    DefaultRandomPoolClass = WinRandomPool

# Try final fallback
if osrandom_source is None and RandomPool is not None:
    osrandom_source = "randompool"
    DefaultRandomPoolClass = FallbackRandomPool

# Give up
if osrandom_source is None:
    raise ImportError("Cannot find OS entropy source")


##
## Define wrapper class
##

class OSRandomPool(object):
    """RandomPool wrapper.

    The C{randpool} attribute of this object may be modified by users of this class at runtime.
    """

    def __init__(self, instance=None):
        if instance is None:
            instance = DefaultRandomPoolClass()
        self.randpool = instance

    def stir(self, s=''):
        self.randpool.stir(s)

    def randomize(self, N=0):
        self.randpool.randomize(N)

    def add_event(self, s=None):
        self.randpool.add_event(s)

    def get_bytes(self, N):
        return self.randpool.get_bytes(N)

# vim:set ts=4 sw=4 sts=4 expandtab:
