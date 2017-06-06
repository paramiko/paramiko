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

import functools
import locale
import os
import unittest

from paramiko.py3compat import (
    builtins,
    )


skip = getattr(unittest, "skip", None)
if skip is None:
    def skip(reason):
        """Stub skip decorator for Python 2.6 compatibility."""
        return lambda func: None


def skipUnlessBuiltin(name):
    """Skip decorated test if builtin name does not exist."""
    if getattr(builtins, name, None) is None:
        return skip("No builtin " + repr(name))
    return lambda func: func


# List of locales which have non-ascii characters in all categories.
# Omits most European languages which for instance may have only some months
# with names that include accented characters.
_non_ascii_locales = [
    # East Asian locales
    "ja_JP", "ko_KR", "zh_CN", "zh_TW",
    # European locales with non-latin alphabets
    "el_GR", "ru_RU", "uk_UA",
]
# Also include UTF-8 versions of these locales
_non_ascii_locales.extend([name + ".utf8" for name in _non_ascii_locales])


def requireNonAsciiLocale(category_name="LC_ALL"):
    """Run decorated test under a non-ascii locale or skip if not possible."""
    if os.name != "posix":
        return skip("Non-posix OSes don't really use C locales")
    cat = getattr(locale, category_name)
    return functools.partial(_decorate_with_locale, cat, _non_ascii_locales)


def _decorate_with_locale(category, try_locales, test_method):
    """Decorate test_method to run after switching to a different locale."""

    def _test_under_locale(testself):
        original = locale.setlocale(category)
        while try_locales:
            try:
                locale.setlocale(category, try_locales[0])
            except locale.Error:
                # Mutating original list is ok, setlocale would keep failing
                try_locales.pop(0)
            else:
                try:
                    return test_method(testself)
                finally:
                    locale.setlocale(category, original)
        skipTest = getattr(testself, "skipTest", None)
        if skipTest is not None:
            skipTest("No usable locales installed")

    functools.update_wrapper(_test_under_locale, test_method)
    return _test_under_locale
