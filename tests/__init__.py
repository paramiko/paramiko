# Copyright (C) 2017 Martin Packman <gzlist@googlemail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""Base classes and helpers for testing paramiko."""

import unittest

from paramiko.py3compat import (
    builtins,
    )


def skipUnlessBuiltin(name):
    """Skip decorated test if builtin name does not exist."""
    if getattr(builtins, name, None) is None:
        skip = getattr(unittest, "skip", None)
        if skip is None:
            # Python 2.6 pseudo-skip
            return lambda func: None
        return skip("No builtin " + repr(name))
    return lambda func: func
