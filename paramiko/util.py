# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
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
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Useful functions used by the rest of paramiko.
"""

from __future__ import annotations

import sys
import struct
import traceback
import threading
import logging

from paramiko.common import (
    DEBUG,
    zero_byte,
    xffffffff,
    max_byte,
    byte_ord,
    byte_chr,
)
from paramiko.config import SSHConfigDict, SSHConfig
from typing import AnyStr, IO, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    import hashlib
    from types import TracebackType
    from typing_extensions import Self
    from _typeshed import FileDescriptorOrPath, ReadableBuffer
    import paramiko.hostkeys


def inflate_long(s: bytes | bytearray, always_positive: bool = False) -> int:
    """turns a normalized byte string into a long-int
    (adapted from Crypto.Util.number)"""
    out = 0
    negative = 0
    if not always_positive and (len(s) > 0) and (byte_ord(s[0]) >= 0x80):
        negative = 1
    if len(s) % 4:
        filler = zero_byte
        if negative:
            filler = max_byte
        # never convert this to ``s +=`` because this is a string, not a number
        # noinspection PyAugmentAssignment
        s = filler * (4 - len(s) % 4) + s
    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack(">I", s[i : i + 4])[0]
    if negative:
        out -= 1 << (8 * len(s))
    return out


def deflate_long(n: int, add_sign_padding: bool = True) -> bytes:
    """turns a long-int into a normalized byte string
    (adapted from Crypto.Util.number)"""
    # after much testing, this algorithm was deemed to be the fastest
    s = bytes()
    n = int(n)
    while (n != 0) and (n != -1):
        s = struct.pack(">I", n & xffffffff) + s
        n >>= 32
    # strip off leading zeros, FFs
    for i in enumerate(s):
        if (n == 0) and (i[1] != 0):
            break
        if (n == -1) and (i[1] != 0xFF):
            break
    else:
        # degenerate case, n was either 0 or -1
        i = (0,)
        if n == 0:
            s = zero_byte
        else:
            s = max_byte
    s = s[i[0] :]
    if add_sign_padding:
        if (n == 0) and (byte_ord(s[0]) >= 0x80):
            s = zero_byte + s
        if (n == -1) and (byte_ord(s[0]) < 0x80):
            s = max_byte + s
    return s


def format_binary(data: bytes | bytearray, prefix: str = "") -> list[str]:
    x = 0
    out = []
    while len(data) > x + 16:
        out.append(format_binary_line(data[x : x + 16]))
        x += 16
    if x < len(data):
        out.append(format_binary_line(data[x:]))
    return [prefix + line for line in out]


def format_binary_line(data: bytes | bytearray) -> str:
    left = " ".join(["{:02X}".format(byte_ord(c)) for c in data])
    right = "".join(
        [".{:c}..".format(byte_ord(c))[(byte_ord(c) + 63) // 95] for c in data]
    )
    return "{:50s} {}".format(left, right)


def safe_string(s: Iterable[int | str]) -> bytes:
    out = b""
    for c in s:
        i = byte_ord(c)
        if 32 <= i <= 127:
            out += byte_chr(i)
        else:
            out += b("%{:02X}".format(i))
    return out


def bit_length(n: int) -> int:
    try:
        return n.bit_length()
    except AttributeError:
        norm = deflate_long(n, False)
        hbyte = byte_ord(norm[0])
        if hbyte == 0:
            return 1
        bitlen = len(norm) * 8
        while not (hbyte & 0x80):
            hbyte <<= 1
            bitlen -= 1
        return bitlen


def tb_strings() -> list[str]:
    return "".join(traceback.format_exception(*sys.exc_info())).split("\n")


def generate_key_bytes(
    hash_alg: type[hashlib._Hash],
    salt: ReadableBuffer,
    key: bytes | str,
    nbytes: int,
) -> bytes:
    """
    Given a password, passphrase, or other human-source key, scramble it
    through a secure hash into some keyworthy bytes.  This specific algorithm
    is used for encrypting/decrypting private key files.

    :param function hash_alg: A function which creates a new hash object, such
        as ``hashlib.sha256``.
    :param salt: data to salt the hash with.
    :type bytes salt: Hash salt bytes.
    :param str key: human-entered password or passphrase.
    :param int nbytes: number of bytes to generate.
    :return: Key data, as `bytes`.
    """
    keydata = bytes()
    digest = bytes()
    if len(salt) > 8:
        salt = salt[:8]
    while nbytes > 0:
        hash_obj = hash_alg()
        if len(digest) > 0:
            hash_obj.update(digest)
        hash_obj.update(b(key))
        hash_obj.update(salt)
        digest = hash_obj.digest()
        size = min(nbytes, len(digest))
        keydata += digest[:size]
        nbytes -= size
    return keydata


def load_host_keys(
    filename: FileDescriptorOrPath,
) -> paramiko.hostkeys.HostKeys:
    """
    Read a file of known SSH host keys, in the format used by openssh, and
    return a compound dict of ``hostname -> keytype ->`` `PKey
    <paramiko.pkey.PKey>`. The hostname may be an IP address or DNS name.

    This type of file unfortunately doesn't exist on Windows, but on posix,
    it will usually be stored in ``os.path.expanduser("~/.ssh/known_hosts")``.

    Since 1.5.3, this is just a wrapper around `.HostKeys`.

    :param str filename: name of the file to read host keys from
    :return:
        nested dict of `.PKey` objects, indexed by hostname and then keytype
    """
    from paramiko.hostkeys import HostKeys

    return HostKeys(filename)


def parse_ssh_config(file_obj: IO[str]) -> SSHConfig:
    """
    Provided only as a backward-compatible wrapper around `.SSHConfig`.

    .. deprecated:: 2.7
        Use `SSHConfig.from_file` instead.
    """
    config = SSHConfig()
    config.parse(file_obj)
    return config


def lookup_ssh_host_config(hostname: str, config: SSHConfig) -> SSHConfigDict:
    """
    Provided only as a backward-compatible wrapper around `.SSHConfig`.
    """
    return config.lookup(hostname)


def mod_inverse(x: int, m: int) -> int:
    # it's crazy how small Python can make this function.
    u1, u2, u3 = 1, 0, m
    v1, v2, v3 = 0, 1, x

    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1 * q
        u2, v2 = v2, u2 - v2 * q
        u3, v3 = v3, u3 - v3 * q
    if u2 < 0:
        u2 += m
    return u2


_g_thread_data = threading.local()
_g_thread_counter = 0
_g_thread_lock = threading.Lock()


def get_thread_id() -> int:
    global _g_thread_data, _g_thread_counter, _g_thread_lock  # noqa
    try:
        return _g_thread_data.id
    except AttributeError:
        with _g_thread_lock:
            _g_thread_counter += 1
            _g_thread_data.id = _g_thread_counter
        return _g_thread_data.id


def log_to_file(filename: FileDescriptorOrPath, level: int = DEBUG) -> None:
    """send paramiko logs to a logfile,
    if they're not already going somewhere"""
    logger = logging.getLogger("paramiko")
    if len(logger.handlers) > 0:
        return
    logger.setLevel(level)
    f = open(filename, "a")
    handler = logging.StreamHandler(f)
    frm = "%(levelname)-.3s [%(asctime)s.%(msecs)03d] thr=%(_threadid)-3d"
    frm += " %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(frm, "%Y%m%d-%H:%M:%S"))
    logger.addHandler(handler)


# make only one filter object, so it doesn't get applied more than once
class PFilter:
    def filter(self, record: logging.LogRecord) -> bool:
        record._threadid = get_thread_id()
        return True


_pfilter = PFilter()


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.addFilter(_pfilter)
    return logger


def constant_time_bytes_eq(a: AnyStr, b: AnyStr) -> bool:
    if len(a) != len(b):
        return False
    res = 0
    # noinspection PyUnresolvedReferences
    for i in range(len(a)):  # noqa: F821
        res |= byte_ord(a[i]) ^ byte_ord(b[i])
    return res == 0


class ClosingContextManager:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def clamp_value(minimum: int, val: int, maximum: int) -> int:
    return max(minimum, min(val, maximum))


def asbytes(s: object) -> object:
    """
    Coerce to bytes if possible or return unchanged.
    """
    try:
        # Attempt to run through our version of b(), which does the Right Thing
        # for unicode strings vs bytestrings, and raises TypeError if it's not
        # one of those types.
        return b(s)
    except TypeError:
        try:
            # If it wasn't a string/byte/buffer-ish object, try calling an
            # asbytes() method, which many of our internal classes implement.
            return s.asbytes()
        except AttributeError:
            # Finally, just do nothing & assume this object is sufficiently
            # byte-y or buffer-y that everything will work out (or that callers
            # are capable of handling whatever it is.)
            return s


# TODO: clean this up / force callers to assume bytes OR unicode
def b(s: str | bytes, encoding: str = "utf8") -> bytes:
    """cast unicode or bytes to bytes"""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode(encoding)
    else:
        raise TypeError(f"Expected unicode or bytes, got {type(s)}")


# TODO: clean this up / force callers to assume bytes OR unicode
def u(s: str | bytes, encoding: str = "utf8") -> str:
    """cast bytes or unicode to unicode"""
    if isinstance(s, bytes):
        return s.decode(encoding)
    elif isinstance(s, str):
        return s
    else:
        raise TypeError(f"Expected unicode or bytes, got {type(s)}")
