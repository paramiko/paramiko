# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Some unit tests for utility functions.
"""

from binascii import hexlify
import cStringIO
import errno
import os
import unittest
from Crypto.Hash import SHA
import paramiko.util


test_config_file = """\
Host *
    User robey
    IdentityFile    =~/.ssh/id_rsa

# comment
Host *.example.com
    \tUser bjork
Port=3333
Host *
 \t  \t Crazy something dumb  
Host spoo.example.com
Crazy something else
"""

test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
"""


# for test 1:
from paramiko import *


class UtilTest (unittest.TestCase):

    assertTrue = unittest.TestCase.failUnless   # for Python 2.3 and below
    assertFalse = unittest.TestCase.failIf      # for Python 2.3 and below

    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_1_import(self):
        """
        verify that all the classes can be imported from paramiko.
        """
        symbols = globals().keys()
        self.assertTrue('Transport' in symbols)
        self.assertTrue('SSHClient' in symbols)
        self.assertTrue('MissingHostKeyPolicy' in symbols)
        self.assertTrue('AutoAddPolicy' in symbols)
        self.assertTrue('RejectPolicy' in symbols)
        self.assertTrue('WarningPolicy' in symbols)
        self.assertTrue('SecurityOptions' in symbols)
        self.assertTrue('SubsystemHandler' in symbols)
        self.assertTrue('Channel' in symbols)
        self.assertTrue('RSAKey' in symbols)
        self.assertTrue('DSSKey' in symbols)
        self.assertTrue('Message' in symbols)
        self.assertTrue('SSHException' in symbols)
        self.assertTrue('AuthenticationException' in symbols)
        self.assertTrue('PasswordRequiredException' in symbols)
        self.assertTrue('BadAuthenticationType' in symbols)
        self.assertTrue('ChannelException' in symbols)
        self.assertTrue('SFTP' in symbols)
        self.assertTrue('SFTPFile' in symbols)
        self.assertTrue('SFTPHandle' in symbols)
        self.assertTrue('SFTPClient' in symbols)
        self.assertTrue('SFTPServer' in symbols)
        self.assertTrue('SFTPError' in symbols)
        self.assertTrue('SFTPAttributes' in symbols)
        self.assertTrue('SFTPServerInterface' in symbols)
        self.assertTrue('ServerInterface' in symbols)
        self.assertTrue('BufferedFile' in symbols)
        self.assertTrue('Agent' in symbols)
        self.assertTrue('AgentKey' in symbols)
        self.assertTrue('HostKeys' in symbols)
        self.assertTrue('SSHConfig' in symbols)
        self.assertTrue('util' in symbols)

    def test_2_parse_config(self):
        global test_config_file
        f = cStringIO.StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        self.assertEquals(config._config,
                          [ {'identityfile': '~/.ssh/id_rsa', 'host': '*', 'user': 'robey',
                             'crazy': 'something dumb  '},
                            {'host': '*.example.com', 'user': 'bjork', 'port': '3333'},
                            {'host': 'spoo.example.com', 'crazy': 'something else'}])

    def test_3_host_config(self):
        global test_config_file
        f = cStringIO.StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        for host, values in {
            'irc.danger.com': {'user': 'robey', 'crazy': 'something dumb  '},
            'irc.example.com': {'user': 'bjork', 'crazy': 'something dumb  ', 'port': '3333'},
            'spoo.example.com': {'user': 'bjork', 'crazy': 'something else', 'port': '3333'}
        }.items():
            values = dict(values,
                hostname=host,
                identityfile=os.path.expanduser("~/.ssh/id_rsa")
            )
            self.assertEquals(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_4_generate_key_bytes(self):
        x = paramiko.util.generate_key_bytes(SHA, 'ABCDEFGH', 'This is my secret passphrase.', 64)
        hex = ''.join(['%02x' % ord(c) for c in x])
        self.assertEquals(hex, '9110e2f6793b69363e58173e9436b13a5a4b339005741d5c680e505f57d871347b4239f14fb5c46e857d5e100424873ba849ac699cea98d729e57b3e84378e8b')

    def test_5_host_keys(self):
        f = open('hostfile.temp', 'w')
        f.write(test_hosts_file)
        f.close()
        try:
            hostdict = paramiko.util.load_host_keys('hostfile.temp')
            self.assertEquals(2, len(hostdict))
            self.assertEquals(1, len(hostdict.values()[0]))
            self.assertEquals(1, len(hostdict.values()[1]))
            fp = hexlify(hostdict['secure.example.com']['ssh-rsa'].get_fingerprint()).upper()
            self.assertEquals('E6684DB30E109B67B70FF1DC5C7F1363', fp)
        finally:
            os.unlink('hostfile.temp')

    def test_6_random(self):
        from paramiko.common import rng
        # just verify that we can pull out 32 bytes and not get an exception.
        x = rng.read(32)
        self.assertEquals(len(x), 32)
        
    def test_7_host_config_expose_issue_33(self):
        test_config_file = """
Host www13.*
    Port 22

Host *.example.com
    Port 2222

Host *
    Port 3333
    """
        f = cStringIO.StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        host = 'www13.example.com'
        self.assertEquals(
            paramiko.util.lookup_ssh_host_config(host, config),
            {'hostname': host, 'port': '22'}
        )

    def test_8_eintr_retry(self):
        self.assertEquals('foo', paramiko.util.retry_on_signal(lambda: 'foo'))

        # Variables that are set by raises_intr
        intr_errors_remaining = [3]
        call_count = [0]
        def raises_intr():
            call_count[0] += 1
            if intr_errors_remaining[0] > 0:
                intr_errors_remaining[0] -= 1
                raise IOError(errno.EINTR, 'file', 'interrupted system call')
        self.assertTrue(paramiko.util.retry_on_signal(raises_intr) is None)
        self.assertEquals(0, intr_errors_remaining[0])
        self.assertEquals(4, call_count[0])

        def raises_ioerror_not_eintr():
            raise IOError(errno.ENOENT, 'file', 'file not found')
        self.assertRaises(IOError,
                          lambda: paramiko.util.retry_on_signal(raises_ioerror_not_eintr))

        def raises_other_exception():
            raise AssertionError('foo')
        self.assertRaises(AssertionError,
                          lambda: paramiko.util.retry_on_signal(raises_other_exception))
