# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
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
Some unit tests for utility functions.
"""

from binascii import hexlify
import os
import stat
from hashlib import sha1
import unittest

import paramiko
import paramiko.util
from paramiko.util import safe_string
from paramiko.sftp_attr import SFTPAttributes
from paramiko.message import Message



test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
"""


class UtilTest(unittest.TestCase):
    def test_imports(self):
        """
        verify that all the classes can be imported from paramiko.
        """
        for name in (
            "Agent",
            "AgentKey",
            "AuthenticationException",
            "AuthFailure",
            "AuthHandler",
            "AuthResult",
            "AuthSource",
            "AuthStrategy",
            "AutoAddPolicy",
            "BadAuthenticationType",
            "BufferedFile",
            "Channel",
            "ChannelException",
            "ConfigParseError",
            "CouldNotCanonicalize",
            "DSSKey",
            "HostKeys",
            "InMemoryPrivateKey",
            "Message",
            "MissingHostKeyPolicy",
            "NoneAuth",
            "OnDiskPrivateKey",
            "Password",
            "PasswordRequiredException",
            "PrivateKey",
            "RSAKey",
            "RejectPolicy",
            "SFTP",
            "SFTPAttributes",
            "SFTPClient",
            "SFTPError",
            "SFTPFile",
            "SFTPHandle",
            "SFTPServer",
            "SFTPServerInterface",
            "SSHClient",
            "SSHConfig",
            "SSHConfigDict",
            "SSHException",
            "SecurityOptions",
            "ServerInterface",
            "SourceResult",
            "SubsystemHandler",
            "Transport",
            "WarningPolicy",
            "util",
        ):
            assert name in dir(paramiko)

    def test_generate_key_bytes(self):
        key_bytes = paramiko.util.generate_key_bytes(
            sha1, b"ABCDEFGH", "This is my secret passphrase.", 64
        )
        hexy = "".join([f"{byte:02x}" for byte in key_bytes])
        hexpected = "9110e2f6793b69363e58173e9436b13a5a4b339005741d5c680e505f57d871347b4239f14fb5c46e857d5e100424873ba849ac699cea98d729e57b3e84378e8b"  # noqa
        assert hexy == hexpected

    def test_host_keys(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)
        try:
            hostdict = paramiko.util.load_host_keys("hostfile.temp")
            assert 2 == len(hostdict)
            assert 1 == len(list(hostdict.values())[0])
            assert 1 == len(list(hostdict.values())[1])
            fp = hexlify(
                hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
            ).upper()
            assert b"E6684DB30E109B67B70FF1DC5C7F1363" == fp
        finally:
            os.unlink("hostfile.temp")

    def test_clamp_value(self):
        assert 32768 == paramiko.util.clamp_value(32767, 32768, 32769)
        assert 32767 == paramiko.util.clamp_value(32767, 32765, 32769)
        assert 32769 == paramiko.util.clamp_value(32767, 32770, 32769)

    def test_safe_string(self):
        vanilla = b"vanilla"
        has_bytes = b"has \7\3 bytes"
        safe_vanilla = safe_string(vanilla)
        safe_has_bytes = safe_string(has_bytes)
        expected_bytes = b"has %07%03 bytes"
        err = "{!r} != {!r}"
        msg = err.format(safe_vanilla, vanilla)
        assert safe_vanilla == vanilla, msg
        msg = err.format(safe_has_bytes, expected_bytes)
        assert safe_has_bytes == expected_bytes, msg
    
    def test_debug_print(self):
        
        test_obj = SFTPAttributes()
        test_obj.st_size = 0
        assert test_obj._debug_str() == "[ size=0 ]"
        
        test_obj.st_uid = 1
        test_obj.st_gid = 2
        assert test_obj._debug_str() == "[ size=0 uid=1 gid=2 ]"
         
        test_obj.st_mode = 10
        assert test_obj._debug_str() == "[ size=0 uid=1 gid=2 mode=0o12 ]"

        test_obj.st_atime = 3
        test_obj.st_mtime = 4
        assert test_obj._debug_str() == "[ size=0 uid=1 gid=2 mode=0o12 atime=3 mtime=4 ]"
        
        test_obj.attr["hey"] = "test"
        assert test_obj._debug_str() == "[ size=0 uid=1 gid=2 mode=0o12 atime=3 mtime=4 \"hey\"='test' ]"


    def test_file_long_description(self):

        test_obj = SFTPAttributes()

        test_obj.st_mode =  stat.S_IFDIR | 0o755
        assert test_obj.__str__() == "drwxr-xr-x   1 0        0               0 (unknown date) ?"

        test_obj.st_mode = stat.S_IFCHR | 0o644
        assert test_obj.__str__() == "crw-r--r--   1 0        0               0 (unknown date) ?"

        test_obj.st_mode = stat.S_IFIFO | 0o644
        assert test_obj.__str__() == "prw-r--r--   1 0        0               0 (unknown date) ?"
        
        test_obj.st_mode = stat.S_IFBLK | 0o644
        assert test_obj.__str__() == "brw-r--r--   1 0        0               0 (unknown date) ?"

        test_obj.st_mode = stat.S_IFREG | 0o644
        assert test_obj.__str__() == "-rw-r--r--   1 0        0               0 (unknown date) ?"

        test_obj.st_mode = stat.S_IFLNK | 0o644
        assert test_obj.__str__() == "lrw-r--r--   1 0        0               0 (unknown date) ?"
        
        test_obj.st_mode = stat.S_IFSOCK | 0o644
        assert test_obj.__str__() == "srw-r--r--   1 0        0               0 (unknown date) ?"
    
        test_obj.st_mode = 1
        assert test_obj.__str__() == "?--------x   1 0        0               0 (unknown date) ?"

    def test_pack(self):
        test_obj = SFTPAttributes()
        test_obj.attr["test1"] = "test_val1"
        test_obj.attr["test2"] = "test_val2"
        test_obj._pack(Message())
        assert test_obj._flags <= test_obj.FLAG_EXTENDED


