# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
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
Some unit tests for HostKeys.
"""

from base64 import decodebytes
from binascii import hexlify
import os
import unittest

import paramiko

from ._util import _support


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
broken.example.com ssh-rsa AAAA
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\
dHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv9\
T9iRZjQzvJd5s+kBAZtpk=
"""

test_hosts_file_tabs = """\
secure.example.com\tssh-rsa\tAAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com\tssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com\tecdsa-sha2-nistp256\tAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml\
zdHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv\
9T9iRZjQzvJd5s+kBAZtpk=
"""

keyblob = b"""\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest(unittest.TestCase):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)

    def tearDown(self):
        os.unlink("hostfile.temp")

    def test_load(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        assert len(hostdict) == 4
        self.assertEqual(1, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)

    def test_add(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        hh = "|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c="
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add(hh, "ssh-rsa", key)
        assert len(hostdict) == 5
        x = hostdict["foo.example.com"]
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        self.assertTrue(hostdict.check("foo.example.com", key))

    def test_dict(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        x = hostdict.get("secure.example.com", None)
        self.assertTrue(x is not None)
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)
        assert list(hostdict) == hostdict.keys()
        assert len(list(hostdict)) == len(hostdict.keys()) == 4

    def test_dict_set(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        key_ed25519 = paramiko.Ed25519Key.from_private_key_file(
            _support("ed25519.key")
        )
        hostdict["secure.example.com"] = {
            "ssh-rsa": key,
            "ssh-ed25519": key_ed25519,
        }
        hostdict["fake.example.com"] = {}
        hostdict["fake.example.com"]["ssh-rsa"] = key

        assert len(hostdict) == 5
        self.assertEqual(2, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        self.assertEqual(1, len(list(hostdict.values())[2]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-ed25519"].get_fingerprint()
        ).upper()
        self.assertEqual(b"B3D522AAF9755EE8CD0EEA02B929A280", fp)

    def test_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        hostdict[target]  # will KeyError if not present
        del hostdict[target]
        try:
            hostdict[target]
        except KeyError:
            pass  # Good
        else:
            assert False, "Entry was not deleted from HostKeys on delitem!"

    def test_entry_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        entry = hostdict[target]
        key_type_list = [key_type for key_type in entry]
        for key_type in key_type_list:
            del entry[key_type]

        # will KeyError if not present
        for key_type in key_type_list:
            try:
                del entry[key_type]
            except KeyError:
                pass  # Good
            else:
                assert False, "Key was not deleted from Entry on delitem!"


class HostKeysTabsTest(HostKeysTest):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file_tabs)
