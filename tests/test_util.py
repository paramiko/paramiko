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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Some unit tests for utility functions.
"""

from binascii import hexlify
import errno
import os
from hashlib import sha1
import unittest

import paramiko.util
from paramiko.util import lookup_ssh_host_config as host_config, safe_string
from paramiko.py3compat import StringIO, byte_ord, b

# Note some lines in this configuration have trailing spaces on purpose
test_config_file = """\
Host *
    User robey
    IdentityFile    =~/.ssh/id_rsa

# comment
Host *.example.com
    \tUser bjork
Port=3333
Host *
"""

dont_strip_whitespace_please = "\t  \t Crazy something dumb  "

test_config_file += dont_strip_whitespace_please
test_config_file += """
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


class UtilTest(unittest.TestCase):
    def test_import(self):
        """
        verify that all the classes can be imported from paramiko.
        """
        symbols = list(globals().keys())
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

    def test_parse_config(self):
        global test_config_file
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        self.assertEqual(config._config,
            [{'host': ['*'], 'config': {}}, {'host': ['*'], 'config': {'identityfile': ['~/.ssh/id_rsa'], 'user': 'robey'}},
            {'host': ['*.example.com'], 'config': {'user': 'bjork', 'port': '3333'}},
            {'host': ['*'], 'config': {'crazy': 'something dumb'}},
            {'host': ['spoo.example.com'], 'config': {'crazy': 'something else'}}])

    def test_host_config(self):
        global test_config_file
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)

        for host, values in {
            'irc.danger.com':   {'crazy': 'something dumb',
                                'hostname': 'irc.danger.com',
                                'user': 'robey'},
            'irc.example.com':  {'crazy': 'something dumb',
                                'hostname': 'irc.example.com',
                                'user': 'robey',
                                'port': '3333'},
            'spoo.example.com': {'crazy': 'something dumb',
                                'hostname': 'spoo.example.com',
                                'user': 'robey',
                                'port': '3333'}
        }.items():
            values = dict(values,
                hostname=host,
                identityfile=[os.path.expanduser("~/.ssh/id_rsa")]
            )
            self.assertEqual(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_generate_key_bytes(self):
        x = paramiko.util.generate_key_bytes(sha1, b'ABCDEFGH', 'This is my secret passphrase.', 64)
        hex = ''.join(['%02x' % byte_ord(c) for c in x])
        self.assertEqual(hex, '9110e2f6793b69363e58173e9436b13a5a4b339005741d5c680e505f57d871347b4239f14fb5c46e857d5e100424873ba849ac699cea98d729e57b3e84378e8b')

    def test_host_keys(self):
        with open('hostfile.temp', 'w') as f:
            f.write(test_hosts_file)
        try:
            hostdict = paramiko.util.load_host_keys('hostfile.temp')
            self.assertEqual(2, len(hostdict))
            self.assertEqual(1, len(list(hostdict.values())[0]))
            self.assertEqual(1, len(list(hostdict.values())[1]))
            fp = hexlify(hostdict['secure.example.com']['ssh-rsa'].get_fingerprint()).upper()
            self.assertEqual(b'E6684DB30E109B67B70FF1DC5C7F1363', fp)
        finally:
            os.unlink('hostfile.temp')

    def test_host_config_expose_issue_33(self):
        test_config_file = """
Host www13.*
    Port 22

Host *.example.com
    Port 2222

Host *
    Port 3333
    """
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        host = 'www13.example.com'
        self.assertEqual(
            paramiko.util.lookup_ssh_host_config(host, config),
            {'hostname': host, 'port': '22'}
        )

    def test_eintr_retry(self):
        self.assertEqual('foo', paramiko.util.retry_on_signal(lambda: 'foo'))

        # Variables that are set by raises_intr
        intr_errors_remaining = [3]
        call_count = [0]
        def raises_intr():
            call_count[0] += 1
            if intr_errors_remaining[0] > 0:
                intr_errors_remaining[0] -= 1
                raise IOError(errno.EINTR, 'file', 'interrupted system call')
        self.assertTrue(paramiko.util.retry_on_signal(raises_intr) is None)
        self.assertEqual(0, intr_errors_remaining[0])
        self.assertEqual(4, call_count[0])

        def raises_ioerror_not_eintr():
            raise IOError(errno.ENOENT, 'file', 'file not found')
        self.assertRaises(IOError,
                          lambda: paramiko.util.retry_on_signal(raises_ioerror_not_eintr))

        def raises_other_exception():
            raise AssertionError('foo')
        self.assertRaises(AssertionError,
                          lambda: paramiko.util.retry_on_signal(raises_other_exception))

    def test_proxycommand_config_equals_parsing(self):
        """
        ProxyCommand should not split on equals signs within the value.
        """
        conf = """
Host space-delimited
    ProxyCommand foo bar=biz baz

Host equals-delimited
    ProxyCommand=foo bar=biz baz
"""
        f = StringIO(conf)
        config = paramiko.util.parse_ssh_config(f)
        for host in ('space-delimited', 'equals-delimited'):
            self.assertEqual(
                host_config(host, config)['proxycommand'],
                'foo bar=biz baz'
            )

    def test_proxycommand_interpolation(self):
        """
        ProxyCommand should perform interpolation on the value
        """
        config = paramiko.util.parse_ssh_config(StringIO("""
Host specific
    Port 37
    ProxyCommand host %h port %p lol

Host portonly
    Port 155

Host *
    Port 25
    ProxyCommand host %h port %p
"""))
        for host, val in (
            ('foo.com', "host foo.com port 25"),
            ('specific', "host specific port 37 lol"),
            ('portonly', "host portonly port 155"),
        ):
            self.assertEqual(
                host_config(host, config)['proxycommand'],
                val
            )

    def test_proxycommand_tilde_expansion(self):
        """
        Tilde (~) should be expanded inside ProxyCommand
        """
        config = paramiko.util.parse_ssh_config(StringIO("""
Host test
    ProxyCommand    ssh -F ~/.ssh/test_config bastion nc %h %p
"""))
        self.assertEqual(
            'ssh -F %s/.ssh/test_config bastion nc test 22' % os.path.expanduser('~'),
            host_config('test', config)['proxycommand']
        )

    def test_host_config_test_negation(self):
        test_config_file = """
Host www13.* !*.example.com
    Port 22

Host *.example.com !www13.*
    Port 2222

Host www13.*
    Port 8080

Host *
    Port 3333
    """
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        host = 'www13.example.com'
        self.assertEqual(
            paramiko.util.lookup_ssh_host_config(host, config),
            {'hostname': host, 'port': '8080'}
        )

    def test_host_config_test_proxycommand(self):
        test_config_file = """
Host proxy-with-equal-divisor-and-space
ProxyCommand = foo=bar

Host proxy-with-equal-divisor-and-no-space
ProxyCommand=foo=bar

Host proxy-without-equal-divisor
ProxyCommand foo=bar:%h-%p
    """
        for host, values in {
            'proxy-with-equal-divisor-and-space'   :{'hostname': 'proxy-with-equal-divisor-and-space',
                                                     'proxycommand': 'foo=bar'},
            'proxy-with-equal-divisor-and-no-space':{'hostname': 'proxy-with-equal-divisor-and-no-space',
                                                     'proxycommand': 'foo=bar'},
            'proxy-without-equal-divisor'          :{'hostname': 'proxy-without-equal-divisor',
                                                     'proxycommand':
                                                     'foo=bar:proxy-without-equal-divisor-22'}
        }.items():

            f = StringIO(test_config_file)
            config = paramiko.util.parse_ssh_config(f)
            self.assertEqual(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_host_config_test_identityfile(self):
        test_config_file = """

IdentityFile id_dsa0

Host *
IdentityFile id_dsa1

Host dsa2
IdentityFile id_dsa2

Host dsa2*
IdentityFile id_dsa22
    """
        for host, values in {
            'foo'   :{'hostname': 'foo',
                      'identityfile': ['id_dsa0', 'id_dsa1']},
            'dsa2'  :{'hostname': 'dsa2',
                      'identityfile': ['id_dsa0', 'id_dsa1', 'id_dsa2', 'id_dsa22']},
            'dsa22' :{'hostname': 'dsa22',
                      'identityfile': ['id_dsa0', 'id_dsa1', 'id_dsa22']}
        }.items():

            f = StringIO(test_config_file)
            config = paramiko.util.parse_ssh_config(f)
            self.assertEqual(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_config_addressfamily_and_lazy_fqdn(self):
        """
        Ensure the code path honoring non-'all' AddressFamily doesn't asplode
        """
        test_config = """
AddressFamily inet
IdentityFile something_%l_using_fqdn
"""
        config = paramiko.util.parse_ssh_config(StringIO(test_config))
        assert config.lookup('meh')  # will die during lookup() if bug regresses

    def test_clamp_value(self):
        self.assertEqual(32768, paramiko.util.clamp_value(32767, 32768, 32769))
        self.assertEqual(32767, paramiko.util.clamp_value(32767, 32765, 32769))
        self.assertEqual(32769, paramiko.util.clamp_value(32767, 32770, 32769))

    def test_config_dos_crlf_succeeds(self):
        config_file = StringIO("host abcqwerty\r\nHostName 127.0.0.1\r\n")
        config = paramiko.SSHConfig()
        config.parse(config_file)
        self.assertEqual(config.lookup("abcqwerty")["hostname"], "127.0.0.1")

    def test_get_hostnames(self):
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        self.assertEqual(config.get_hostnames(), set(['*', '*.example.com', 'spoo.example.com']))

    def test_quoted_host_names(self):
        test_config_file = """\
Host "param pam" param "pam"
    Port 1111

Host "param2"
    Port 2222

Host param3 parara
    Port 3333

Host param4 "p a r" "p" "par" para
    Port 4444
"""
        res = {
            'param pam': {'hostname': 'param pam', 'port': '1111'},
            'param': {'hostname': 'param', 'port': '1111'},
            'pam': {'hostname': 'pam', 'port': '1111'},

            'param2': {'hostname': 'param2', 'port': '2222'},

            'param3': {'hostname': 'param3', 'port': '3333'},
            'parara': {'hostname': 'parara', 'port': '3333'},

            'param4': {'hostname': 'param4', 'port': '4444'},
            'p a r': {'hostname': 'p a r', 'port': '4444'},
            'p': {'hostname': 'p', 'port': '4444'},
            'par': {'hostname': 'par', 'port': '4444'},
            'para': {'hostname': 'para', 'port': '4444'},
        }
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        for host, values in res.items():
            self.assertEquals(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_quoted_params_in_config(self):
        test_config_file = """\
Host "param pam" param "pam"
    IdentityFile id_rsa

Host "param2"
    IdentityFile "test rsa key"

Host param3 parara
    IdentityFile id_rsa
    IdentityFile "test rsa key"
"""
        res = {
            'param pam': {'hostname': 'param pam', 'identityfile': ['id_rsa']},
            'param': {'hostname': 'param', 'identityfile': ['id_rsa']},
            'pam': {'hostname': 'pam', 'identityfile': ['id_rsa']},

            'param2': {'hostname': 'param2', 'identityfile': ['test rsa key']},

            'param3': {'hostname': 'param3', 'identityfile': ['id_rsa', 'test rsa key']},
            'parara': {'hostname': 'parara', 'identityfile': ['id_rsa', 'test rsa key']},
        }
        f = StringIO(test_config_file)
        config = paramiko.util.parse_ssh_config(f)
        for host, values in res.items():
            self.assertEquals(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_quoted_host_in_config(self):
        conf = SSHConfig()
        correct_data = {
            'param': ['param'],
            '"param"': ['param'],

            'param pam': ['param', 'pam'],
            '"param" "pam"': ['param', 'pam'],
            '"param" pam': ['param', 'pam'],
            'param "pam"': ['param', 'pam'],

            'param "pam" p': ['param', 'pam', 'p'],
            '"param" pam "p"': ['param', 'pam', 'p'],

            '"pa ram"': ['pa ram'],
            '"pa ram" pam': ['pa ram', 'pam'],
            'param "p a m"': ['param', 'p a m'],
        }
        incorrect_data = [
            'param"',
            '"param',
            'param "pam',
            'param "pam" "p a',
        ]
        for host, values in correct_data.items():
            self.assertEquals(
                conf._get_hosts(host),
                values
            )
        for host in incorrect_data:
            self.assertRaises(Exception, conf._get_hosts, host)

    def test_safe_string(self):
        vanilla = b("vanilla")
        has_bytes = b("has \7\3 bytes")
        safe_vanilla = safe_string(vanilla)
        safe_has_bytes = safe_string(has_bytes)
        expected_bytes = b("has %07%03 bytes")
        err = "{0!r} != {1!r}"
        msg = err.format(safe_vanilla, vanilla)
        assert safe_vanilla == vanilla, msg
        msg = err.format(safe_has_bytes, expected_bytes)
        assert safe_has_bytes == expected_bytes, msg

    def test_proxycommand_none_issue_418(self):
        test_config_file = """
Host proxycommand-standard-none
    ProxyCommand None

Host proxycommand-with-equals-none
    ProxyCommand=None
    """
        for host, values in {
            'proxycommand-standard-none':    {'hostname': 'proxycommand-standard-none'},
            'proxycommand-with-equals-none': {'hostname': 'proxycommand-with-equals-none'}
        }.items():

            f = StringIO(test_config_file)
            config = paramiko.util.parse_ssh_config(f)
            self.assertEqual(
                paramiko.util.lookup_ssh_host_config(host, config),
                values
            )

    def test_proxycommand_none_masking(self):
        # Re: https://github.com/paramiko/paramiko/issues/670
        source_config = """
Host specific-host
    ProxyCommand none

Host other-host
    ProxyCommand other-proxy

Host *
    ProxyCommand default-proxy
"""
        config = paramiko.SSHConfig()
        config.parse(StringIO(source_config))
        # When bug is present, the full stripping-out of specific-host's
        # ProxyCommand means it actually appears to pick up the default
        # ProxyCommand value instead, due to cascading. It should (for
        # backwards compatibility reasons in 1.x/2.x) appear completely blank,
        # as if the host had no ProxyCommand whatsoever.
        # Threw another unrelated host in there just for sanity reasons.
        self.assertFalse('proxycommand' in config.lookup('specific-host'))
        self.assertEqual(
            config.lookup('other-host')['proxycommand'],
            'other-proxy'
        )
        self.assertEqual(
            config.lookup('some-random-host')['proxycommand'],
            'default-proxy'
        )
