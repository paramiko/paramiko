"""Base classes and helpers for testing paramiko."""

import functools
import locale
import os

from pytest import skip


# List of locales which have non-ascii characters in all categories.
# Omits most European languages which for instance may have only some months
# with names that include accented characters.
_non_ascii_locales = [
    # East Asian locales
    "ja_JP",
    "ko_KR",
    "zh_CN",
    "zh_TW",
    # European locales with non-latin alphabets
    "el_GR",
    "ru_RU",
    "uk_UA",
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

    def _test_under_locale(testself, *args, **kwargs):
        original = locale.setlocale(category)
        while try_locales:
            try:
                locale.setlocale(category, try_locales[0])
            except locale.Error:
                # Mutating original list is ok, setlocale would keep failing
                try_locales.pop(0)
            else:
                try:
                    return test_method(testself, *args, **kwargs)
                finally:
                    locale.setlocale(category, original)
        # No locales could be used? Just skip the decorated test :(
        skip("No usable locales installed")

    functools.update_wrapper(_test_under_locale, test_method)
    return _test_under_locale
