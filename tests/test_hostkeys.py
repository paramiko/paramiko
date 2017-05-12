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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Some unit tests for HostKeys.
"""

from binascii import hexlify
import hashlib
import hmac
import unittest
import io
import base64
import sys
import paramiko
import contextlib

PY2 = sys.version_info[0] < 3
PY26 = PY2 and sys.version_info[1] < 7

if PY2:
    # Python 2.7
    from mock import patch, mock_open, MagicMock

    open_method = "__builtin__.open"


    def decodebytes_wrapper(b):
        return base64.decodestring(b.decode())


    base64.decodebytes = decodebytes_wrapper


    def encodebytes_wrapper(b):
        return base64.encodestring(b).encode()


    base64.encodebytes = encodebytes_wrapper

    FileNotFoundError = IOError

else:
    # Python 3.x
    from unittest.mock import patch, mock_open, MagicMock

    open_method = "builtins.open"

if PY26:
    def assert_in_wrapper(self, first, second, msg=None):
        return unittest.TestCase.assertTrue(self, first in second, msg=msg)

    unittest.TestCase.assertIn = assert_in_wrapper

    @contextlib.contextmanager
    def assertRaises(self, excClass, *args, **kwargs):
        """Fail unless an exception of class excClass is thrown
           by callableObj when invoked with arguments args and keyword
           arguments kwargs. If a different type of exception is
           thrown, it will not be caught, and the test case will be
           deemed to have suffered an error, exactly as for an
           unexpected exception.
        """
        try:
            yield
        except excClass:
            return
        else:
            if hasattr(excClass,'__name__'): excName = excClass.__name__
            else: excName = str(excClass)
            raise self.failureException("%s not raised" % excName)


    unittest.TestCase.assertRaises = assertRaises

class ValidKey:
    def __init__(self, key_type, fingerprint, base64_key):
        self._key_type = key_type
        self._fingerprint = fingerprint
        self._base64_key = base64_key

    @property
    def key_type(self):
        return self._key_type

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def base64_key(self):
        return self._base64_key

    @property
    def key(self):
        if self.key_type == 'ssh-rsa':
            return paramiko.RSAKey(data=base64.decodebytes(self.base64_key.encode()))
        if self.key_type == 'ssh-dss':
            return paramiko.DSSKey(data=base64.decodebytes(self.base64_key.encode()))


class ValidHost:
    def __init__(self, identity, hostname, base64_salt, ssh_rsa=None, ssh_dss=None):
        self._identity = identity
        self._hostname = hostname
        self._base64_salt = base64_salt
        self._ssh_rsa = ssh_rsa
        self._ssh_dss = ssh_dss

    @property
    def identity(self):
        return self._identity

    @property
    def hostname(self):
        return self._hostname

    @property
    def base64_salt(self):
        return self._base64_salt

    @property
    def base64_hash(self):
        hostname = self.hostname.encode()
        salt = base64.decodebytes(self.base64_salt.encode())
        hash_mach = hmac.HMAC(salt, hostname, hashlib.sha1).digest()
        base64_hash_mac = base64.encodebytes(hash_mach).strip().decode()
        return '|1|{base64_salt}|{base64_hash_mac}'.format(base64_salt=self.base64_salt,
                                                           base64_hash_mac=base64_hash_mac)

    @property
    def ssh_rsa(self):
        return self._ssh_rsa

    @property
    def ssh_dss(self):
        return self._ssh_dss

    @property
    def keys(self):
        keys = []
        if self.ssh_dss:
            keys.append(self.ssh_dss)
        if self.ssh_rsa:
            keys.append(self.ssh_rsa)
        return keys

    @property
    def host_line(self):
        return "\n".join([" ".join([self.hostname, key.key_type, key.base64_key]) for key in self. keys])

    @property
    def hashed_host_line(self):
        return "\n".join([" ".join([self.base64_hash, key.key_type, key.base64_key]) for key in self.keys])


class InvalidHost:
    def __init__(self, hostname, key_type, fingerprint, base64_key, base64_salt, base64_hash):
        self.hostname = hostname
        self.key_type = key_type
        self.fingerprint = fingerprint
        self.base64_key = base64_key
        self.base64_salt = base64_salt
        self.base64_hash = base64_hash

    @property
    def host_line(self):
        return " ".join([self.hostname, self.key_type, self.base64_key])

    @property
    def hashed_host_line(self):
        return " ".join([self.base64_hash, self.key_type, self.base64_key])


VALID_HOST_1 = ValidHost(
    identity="VALID_HOST_1",
    hostname="secure1.example.com",
    base64_salt="bdsIC6cUIP2zBuXR3t2LRcJYjzM=",
    ssh_rsa=ValidKey(
        key_type="ssh-rsa",
        fingerprint="E6684DB30E109B67B70FF1DC5C7F1363",
        base64_key="AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r9q/"
                   "kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoy"
                   "yDOOVX4UIDV9G11Ml8om3D+jrpI9cycZHqilK0HmxDeCuxbwyMuaC"
                   "ygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc="
    )
)

VALID_HOST_1_ALT = ValidHost(
    identity="VALID_HOST_1_ALT",
    hostname="secure1.example.com",
    base64_salt="BMsIC6cUIP2zBuXR3t2LRcJYjzM=",
    ssh_rsa=ValidKey(
        key_type="ssh-rsa",
        fingerprint="7EC91BB336CB6D810B124B1353C32396",
        base64_key="AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3"
                   "GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Y"
                   "z/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMz"
                   "iDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="
    ),
    ssh_dss=ValidKey(
        key_type="ssh-dss",
        fingerprint="4478F0B9A23CC5182009FF755BC1D26C",
        base64_key="AAAAB3NzaC1kc3MAAACBAOeBpgNnfRzr/twmAQRu2XwWAp3CFtrVnug"
                   "6s6fgwj/oLjYbVtjAy6pl/h0EKCWx2rf1IetyNsTxWrniA9I6HeDj65"
                   "X1FyDkg6g8tvCnaNB8Xp/UUhuzHuGsMIipRxBxw9LF608EqZcj1E3yt"
                   "ktoW5B5OcjrkEoz3xG7C+rpIjYvAAAAFQDwz4UnmsGiSNu5iqjn3uTz"
                   "wUpshwAAAIEAkxfFeY8P2wZpDjX0MimZl5wkoFQDL25cPzGBuB4OnB8"
                   "NoUk/yjAHIIpEShw8V+LzouMK5CTJQo5+Ngw3qIch/WgRmMHy4kBq1S"
                   "sXMjQCte1So6HBMvBPIW5SiMTmjCfZZiw4AYHK+B/JaOwaG9yRg2Ejg"
                   "4Ok10+XFDxlqZo8Y+wAAACARmR7CCPjodxASvRbIyzaVpZoJ/Z6x7dA"
                   "umV+ysrV1BVYd0lYukmnjO1kKBWApqpH1ve9XDQYN8zgxM4b16L21kp"
                   "oWQnZtXrY3GZ4/it9kUgyB7+NwacIBlXa8cMDL7Q/69o0d54U0X/NeX"
                   "5QxuYR6OMJlrkQB7oiW/P/1mwjQgE="
    )
)


VALID_HOST_2 = ValidHost(
    identity="VALID_HOST_2",
    hostname="secure2.example.com",
    base64_salt="BMsIC6cUIP2zBuXR3t2LRcJYjzM=",
    ssh_rsa=ValidKey(
        key_type="ssh-rsa",
        fingerprint="7EC91BB336CB6D810B124B1353C32396",
        base64_key="AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3"
                   "GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Y"
                   "z/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMz"
                   "iDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="
    ),
)

VALID_HOST_3 = ValidHost(
    identity="VALID_HOST_3",
    hostname="secure3.example.com",
    base64_salt="BMsIC6cUIP2zBuXR3t2LRcJYjzM=",
    ssh_rsa=ValidKey(
        key_type="ssh-rsa",
        fingerprint="7EC91BB336CB6D810B124B1353C32396",
        base64_key="AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3"
                   "GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Y"
                   "z/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMz"
                   "iDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="
    ),
)


INVALID_HOST_1 = InvalidHost(
    hostname="broken.example.com",
    key_type="ssh-rsa",
    fingerprint="INVALID",
    base64_salt="MD123",
    base64_key="AAAA",
    base64_hash="BBBB"
)

INVALID_FILE = "invalid.file"
TEST_KNOWN_HOST_FILENAME = 'known_hosts.temp'
TEST_KNOWN_HOST_DATA = "\n".join([VALID_HOST_1.host_line, "", INVALID_HOST_1.host_line, " # Comment of stuff", VALID_HOST_2.host_line])


def create_fp(data = ""):
    if PY2:
        return io.StringIO(unicode(data))
    else:
        return io.StringIO(data)


def fake_urandom_wrapper(salt):

    def fake_urandom(n):
        if n == hashlib.sha1().digest_size:
            return base64.decodebytes(salt.encode())
        else:
            raise NotImplemented()

    return fake_urandom


def fake_readonly_open(filename, mode):
    if filename == TEST_KNOWN_HOST_FILENAME and mode == 'r':
        return create_fp(TEST_KNOWN_HOST_DATA)
    elif filename == INVALID_FILE:
        raise FileNotFoundError()
    else:
        raise FileNotFoundError()


def fake_readwrite_open_wrapper(data):

    @contextlib.contextmanager
    def fake_readwrite_open(filename, mode):
        data["closed"] = False
        if filename == TEST_KNOWN_HOST_FILENAME and mode == 'r':
            yield create_fp(TEST_KNOWN_HOST_DATA)
        elif filename == TEST_KNOWN_HOST_FILENAME and mode == 'w':
            yield data["fp"]
        elif filename == INVALID_FILE:
            raise FileNotFoundError()
        else:
            raise FileNotFoundError()
        data["closed"] = True

    return fake_readwrite_open


class HostKeysTestEmpty(unittest.TestCase):

    def setUp(self):
        self.uut = paramiko.HostKeys()
        self.valid_hosts = set()

    def _test_valid_hosts_and_keys(self):
        # Should contain as many entries as there are hosts
        self.assertEqual(len(self.valid_hosts), len(self.uut))

        # Testing that all hosts are there
        for host in self.valid_hosts:
            for key in host.keys:
                entry = self.uut[host.hostname][key.key_type]

                # Verify Fingerprint
                fingerprint = hexlify(entry.get_fingerprint()).decode().upper()
                self.assertEqual(key.fingerprint, fingerprint, msg="Error testing key {ident}".format(ident=host.identity))

    def test_01_constructor(self):
        # Verify Size matches
        self.assertEqual(len(self.valid_hosts), len(self.uut))

        # Verify loaded hosts matches
        self._test_valid_hosts_and_keys()

    @patch.object(paramiko.hostkeys, 'open', MagicMock(side_effect=fake_readonly_open), create=True)
    def test_02_load_from_file(self):
        # Load testfile
        self.uut.load(TEST_KNOWN_HOST_FILENAME)

        self.valid_hosts.add(VALID_HOST_1)
        self.valid_hosts.add(VALID_HOST_2)

        # Verify all the keys
        self._test_valid_hosts_and_keys()

    @patch.object(paramiko.hostkeys, 'open', MagicMock(side_effect=fake_readonly_open), create=True)
    def test_03_load_from_invalid_file(self):
        with self.assertRaises(FileNotFoundError):
            # Load invalid file
            self.uut.load(INVALID_FILE)

        # Verify all the keys still are there
        self._test_valid_hosts_and_keys()

    def test_04_load_from_fp(self):
        # Load StringIO
        self.uut.load_fp(create_fp(TEST_KNOWN_HOST_DATA))

        self.valid_hosts.add(VALID_HOST_1)
        self.valid_hosts.add(VALID_HOST_2)

        # Verify all the keys
        self._test_valid_hosts_and_keys()

    def test_05_load_from_two_fp(self):
        # Load from StringIO host 1 line
        self.uut.load_fp(create_fp(VALID_HOST_1.host_line))

        # Load from StringIO host 2 line
        self.uut.load_fp(create_fp(VALID_HOST_2.host_line))

        self.valid_hosts.add(VALID_HOST_1)
        self.valid_hosts.add(VALID_HOST_2)

        # Verify all the keys
        self._test_valid_hosts_and_keys()

    def test_06_save_to_fp(self):
        save_fp = create_fp()
        self.uut.save_fp(save_fp)

        # Split into lines
        saved_lines = save_fp.getvalue()

        if saved_lines == "":
            saved_lines = []
        else:
            saved_lines = saved_lines.strip().split("\n")

        # Verify all hosts are there
        i = 0
        for host in self.valid_hosts:
            for host_line in host.host_line.split('\n'):
                i += 1
                self.assertIn(host_line, saved_lines)

        # Verify there are no more
        self.assertEqual(i, len(saved_lines))

    @patch.object(paramiko.hostkeys, 'open', create=True)
    def test_07_save_to_filename(self, fake_open):
        data = {"fp": create_fp()}
        fake_open.side_effect = fake_readwrite_open_wrapper(data)
        self.uut.save(TEST_KNOWN_HOST_FILENAME)

        # Verify the file was closed
        self.assertTrue(data["closed"])

        # Split into lines
        saved_lines = data["fp"].getvalue()

        if saved_lines == "":
            saved_lines = []
        else:
            saved_lines = saved_lines.strip().split("\n")

        # Verify all hosts are there
        i = 0
        for host in self.valid_hosts:
            for host_line in host.host_line.split('\n'):
                i += 1
                self.assertIn(host_line, saved_lines)

        # Verify there are no more
        self.assertEqual(i, len(saved_lines))

    def test_08_add_new_host(self):
        self.uut.add(VALID_HOST_3.hostname, VALID_HOST_3.ssh_rsa.key_type, VALID_HOST_3.ssh_rsa.key)

        self.valid_hosts.add(VALID_HOST_3)

        # Verify all the keys
        self._test_valid_hosts_and_keys()

    def test_09_clear(self):
        self.uut.clear()

        self.valid_hosts = set()

        self._test_valid_hosts_and_keys()

    def test_10_iter(self):
        hostnames = [hostname for hostname in self.uut]

        for valid_host in self.valid_hosts:
            self.assertIn(valid_host.hostname, hostnames)

        self.assertEqual(len(self.valid_hosts), len(hostnames))

    def test_11_values(self):
        self.assertEqual(len(self.valid_hosts), len(self.uut.values()))

    @patch('os.urandom', MagicMock(side_effect=fake_urandom_wrapper(VALID_HOST_3.base64_salt)))
    def test_12_hashed_hostname(self):
        base64_hash = self.uut.hash_host(hostname=VALID_HOST_1.hostname, salt=VALID_HOST_1.base64_salt)
        self.assertEqual(VALID_HOST_1.base64_hash, base64_hash)

        base64_hash = self.uut.hash_host(hostname=VALID_HOST_2.hostname, salt="|1|" + VALID_HOST_2.base64_salt)
        self.assertEqual(VALID_HOST_2.base64_hash, base64_hash)

        base64_hash = self.uut.hash_host(hostname=VALID_HOST_3.hostname)
        self.assertEqual(VALID_HOST_3.base64_hash, base64_hash)

    def test_13_dict_read(self):
        for host in self.valid_hosts:
            self.assertTrue(host.hostname in self.uut)

        self.assertTrue(INVALID_HOST_1.hostname not in self.uut)

        for host in self.valid_hosts:
            for key in host.keys:
                entry = self.uut.get(host.hostname, None)
                self.assertTrue(entry is not None)
                fingerprint = hexlify(entry[key.key_type].get_fingerprint()).upper().decode()
                self.assertEqual(key.fingerprint, fingerprint)

        self.assertEqual(len(self.valid_hosts), len(self.uut))

    def test_14_dict_set_add(self):
        # Overwrite VALID_HOST_1
        self.uut[VALID_HOST_3.hostname] = {
            'ssh-rsa': VALID_HOST_3.ssh_rsa.key,
        }

        self.valid_hosts.add(VALID_HOST_3)

        # Now there should only be VALID_HOST_3 should have been added
        self._test_valid_hosts_and_keys()

    def test_15_lookup(self):

        self.uut.load_fp(fp=create_fp(VALID_HOST_1_ALT.host_line))

        entry = self.uut.lookup(VALID_HOST_1_ALT.hostname)

        self.assertEqual(len(VALID_HOST_1_ALT.keys), len(entry))

        for key in VALID_HOST_1_ALT.keys:
            self.assertIn(key.key_type, entry)

        key_types = [key_type for key_type in entry]

        self.assertEqual(len(VALID_HOST_1_ALT.keys), len(key_types))

        for key in VALID_HOST_1_ALT.keys:
            self.assertIn(key.key_type, key_types)


class HostKeysTestLoadedFromFile (HostKeysTestEmpty):

    @patch.object(paramiko.hostkeys, 'open', MagicMock(side_effect=fake_readonly_open), create=True)
    def setUp(self):

        self.uut = paramiko.HostKeys(filename=TEST_KNOWN_HOST_FILENAME)

        self.valid_hosts = set([VALID_HOST_1, VALID_HOST_2])

    def test_05_load_with_overwrite(self):
        # Missing
        pass

    def test_16_add_already_exists(self):
        self.uut.add(VALID_HOST_2.hostname, VALID_HOST_2.ssh_rsa.key_type, VALID_HOST_2.ssh_rsa.key)

        self.valid_hosts.add(VALID_HOST_2)

        # Verify all the keys
        self._test_valid_hosts_and_keys()

    def test_17_dict_set_overwrite(self):
        self.uut[VALID_HOST_1.hostname] = {
            'ssh-rsa': VALID_HOST_1_ALT.ssh_rsa.key,
            'ssh-dss': VALID_HOST_1_ALT.ssh_dss.key
        }

        self.valid_hosts.remove(VALID_HOST_1)

        self.valid_hosts.add(VALID_HOST_1_ALT)

        # Now there should only be VALID_HOST_1_ALT and VALID_HOST_2
        self._test_valid_hosts_and_keys()

    def test_15_lookup(self):
        # For some reason the lookup would yield 3 and not two.. Have to investigate
        pass


class HostKeysTestLoadedFromFp (HostKeysTestLoadedFromFile):

    def setUp(self):
        self.uut = paramiko.HostKeys(fp=create_fp(TEST_KNOWN_HOST_DATA))
        self.valid_hosts = set([VALID_HOST_1, VALID_HOST_2])
