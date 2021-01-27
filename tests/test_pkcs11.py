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
Test the used APIs for pkcs11
"""

import unittest
import mock
from paramiko import pkcs11
from paramiko.pkcs11 import PKCS11Exception 
from paramiko.auth_handler import AuthHandler
from paramiko.transport import Transport
from tests.loop import LoopSocket


test_rsa_public_key = b"ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA049W6geFpmsljTwfvI1UmKWWJPNFI74+vNKTk4dmzkQY2yAMs6FhlvhlI8ysU4oj71ZsRYMecHbBbxdN79+JRFVYTKaLqjwGENeTd+yv4q+V2PvZv3fLnzApI3l7EJCqhWwJUHJ1jAkZzqDx0tyOL4uoZpww3nmE0kb3y21tH4c=" # noqa


class MockPKCS11Lib(object):
    def __init__(self):
        pass

    def C_Finalize(val):
        return 0

    def C_Initialize(val1, val2):
        return 0

    def C_OpenSession(val1, val2, val3, val4, val5, val6):
        return 0

    def C_Login(val1, val2, val3, val4, val5):
        return 0

    def C_FindObjectsInit(val1, val2, val3, val4):
        return 0

    def C_FindObjects(val1, val2, val3, val4, val5):
        return 0

    def C_FindObjectsFinal(val1, val2):
        return 0

    def C_Sign(val1, val2, val3, val4, val5, val6):
        return 0

    def C_SignInit(val1, val2, val3, val4):
        return 0


class MockPopen_pkcs15tool_rsakey(object):
    def __init__(self, stdout, stderr):
        self.stdout = stdout
        self.stderr = stderr
        self.stdout = test_rsa_public_key

    def communicate(self):
        return (self.stdout, self.stderr)

    def wait(self):
        pass

    def kill(self):
        pass


class Pkcs11Test(unittest.TestCase):
    def setUp(self):
        self.sockc = LoopSocket()

    def tearDown(self):
        pass

    @mock.patch('subprocess.Popen',
                return_value=MockPopen_pkcs15tool_rsakey([], []))
    def test_1_pkcs11_get_public_key(self, mock_popen):
        """
        Test Getting Public Key
        """
        public_key = pkcs11.get_public_key()
        self.assertEqual(public_key, test_rsa_public_key.decode("utf-8"))

    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('paramiko.pkcs11.cdll.LoadLibrary',
                return_value=MockPKCS11Lib())
    def test_2_pkcs11_close_session_success(self,
                                            mock_isfile,
                                            mock_loadlibrary):
        pkcs11_session = {"pkcs11provider": "/test/path/example"}
        threw_exception = True
        try:
            pkcs11.close_session(pkcs11_session)
        except Exception:
            threw_exception = False
        self.assertTrue(not threw_exception)

    @mock.patch('os.path.isfile', return_value=False)
    @mock.patch('paramiko.pkcs11.cdll.LoadLibrary',
                return_value=MockPKCS11Lib())
    def test_3_pkcs11_close_session_fail_nofile(self, mock_isfile,
                                                mock_loadlibrary):
        pkcs11_session = {"pkcs11provider": "/test/path/example"}
        threw_exception = False
        try:
            pkcs11.close_session(pkcs11_session)
        except PKCS11Exception:
            threw_exception = True
        self.assertTrue(threw_exception)

    @mock.patch('subprocess.Popen',
                return_value=MockPopen_pkcs15tool_rsakey([], []))
    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('paramiko.pkcs11.cdll.LoadLibrary',
                return_value=MockPKCS11Lib())
    def test_4_pkcs11_open_session(self,
                                   mock_popen,
                                   mock_isfile,
                                   mock_loadlibrary):
        session = pkcs11.open_session("/test/provider/example", "1234")
        self.assertEqual(0, session["session"].value)
        self.assertEqual(test_rsa_public_key.decode("utf-8"), session["public_key"])
        self.assertEqual(0, session["keyret"].value)
        self.assertEqual("/test/provider/example", session["provider"])

    @mock.patch('paramiko.auth_handler.AuthHandler._request_auth',
                return_value=True)
    def test_5_pkcs11_authhandler_auth_pkcs11_basic(self, mock_requestauth):
        # Mock _request_auth just to test the setup
        # Just test the setup
        tc = Transport(self.sockc)
        session = {"session": None}
        testauth = AuthHandler(tc)
        testauth.auth_pkcs11("testuser", session, None)
        self.assertEqual(testauth.auth_event, None)
        self.assertEqual(testauth.auth_method, 'publickey')
        self.assertEqual(testauth.username, "testuser")
        self.assertEqual(testauth.pkcs11_session, session)

    @mock.patch('paramiko.auth_handler.AuthHandler._request_auth',
                return_value=True)
    def test_6_pkcs11_authhandler_pkcs11_get_public_key(self, mock_requestauth):
        tc = Transport(self.sockc)
        session = {"public_key": test_rsa_public_key}
        testauth = AuthHandler(tc)
        testauth.auth_pkcs11("testuser", session, None)
        public_key = testauth._pkcs11_get_public_key()
        self.assertEqual(public_key, test_rsa_public_key)