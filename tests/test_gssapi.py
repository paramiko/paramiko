# Copyright (C) 2013-2014 science + computing ag
# Author: Sebastian Deiss <sebastian.deiss@t-online.de>
#
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
Test the used APIs for GSS-API / SSPI authentication
"""

import socket

from .util import KerberosTestCase, update_env


class GSSAPITest(KerberosTestCase):
    def setUp(self):
        super(GSSAPITest, self).setUp()
        self.krb5_mech = "1.2.840.113554.1.2.2"
        self.targ_name = self.realm.hostname
        self.server_mode = False
        update_env(self, self.realm.env)

    def test_pyasn1(self):
        """
        Test the used methods of pyasn1.
        """
        from pyasn1.type.univ import ObjectIdentifier
        from pyasn1.codec.der import encoder, decoder
        oid = encoder.encode(ObjectIdentifier(self.krb5_mech))
        mech, __ = decoder.decode(oid)
        self.assertEqual(self.krb5_mech, mech.__str__())

    def _gssapi_sspi_test(self):
        """
        Test the used methods of python-gssapi or sspi, sspicon from pywin32.
        """
        try:
            import gssapi
            if (hasattr(gssapi, '__title__') and
                    gssapi.__title__ == 'python-gssapi'):
                _API = "MIT"
            else:
                _API = "MIT-NEW"
        except ImportError:
            import sspicon
            import sspi
            _API = "SSPI"

        c_token = None
        gss_ctxt_status = False
        mic_msg = b"G'day Mate!"

        if _API == "MIT":
            if self.server_mode:
                gss_flags = (gssapi.C_PROT_READY_FLAG,
                             gssapi.C_INTEG_FLAG,
                             gssapi.C_MUTUAL_FLAG,
                             gssapi.C_DELEG_FLAG)
            else:
                gss_flags = (gssapi.C_PROT_READY_FLAG,
                             gssapi.C_INTEG_FLAG,
                             gssapi.C_DELEG_FLAG)
            # Initialize a GSS-API context.
            ctx = gssapi.Context()
            ctx.flags = gss_flags
            krb5_oid = gssapi.OID.mech_from_string(self.krb5_mech)
            target_name = gssapi.Name("host@" + self.targ_name,
                                      gssapi.C_NT_HOSTBASED_SERVICE)
            gss_ctxt = gssapi.InitContext(peer_name=target_name,
                                          mech_type=krb5_oid,
                                          req_flags=ctx.flags)
            if self.server_mode:
                c_token = gss_ctxt.step(c_token)
                gss_ctxt_status = gss_ctxt.established
                self.assertEqual(False, gss_ctxt_status)
                # Accept a GSS-API context.
                gss_srv_ctxt = gssapi.AcceptContext()
                s_token = gss_srv_ctxt.step(c_token)
                gss_ctxt_status = gss_srv_ctxt.established
                self.assertNotEqual(None, s_token)
                self.assertEqual(True, gss_ctxt_status)
                # Establish the client context
                c_token = gss_ctxt.step(s_token)
                self.assertEqual(None, c_token)
            else:
                while not gss_ctxt.established:
                    c_token = gss_ctxt.step(c_token)
                self.assertNotEqual(None, c_token)
            # Build MIC
            mic_token = gss_ctxt.get_mic(mic_msg)

            if self.server_mode:
                # Check MIC
                status = gss_srv_ctxt.verify_mic(mic_msg, mic_token)
                self.assertEqual(0, status)

        elif _API == "MIT-NEW":
            if self.server_mode:
                gss_flags = (gssapi.RequirementFlag.protection_ready,
                             gssapi.RequirementFlag.integrity,
                             gssapi.RequirementFlag.mutual_authentication,
                             gssapi.RequirementFlag.delegate_to_peer)
            else:
                gss_flags = (gssapi.RequirementFlag.protection_ready,
                             gssapi.RequirementFlag.integrity,
                             gssapi.RequirementFlag.delegate_to_peer)
            # Initialize a GSS-API context.
            krb5_oid = gssapi.MechType.kerberos
            target_name = gssapi.Name("host@" + self.targ_name,
                                name_type=gssapi.NameType.hostbased_service)
            gss_ctxt = gssapi.SecurityContext(name=target_name,
                                              flags=gss_flags,
                                              mech=krb5_oid,
                                              usage='initiate')
            if self.server_mode:
                c_token = gss_ctxt.step(c_token)
                gss_ctxt_status = gss_ctxt.complete
                self.assertEqual(False, gss_ctxt_status)
                # Accept a GSS-API context.
                gss_srv_ctxt = gssapi.SecurityContext(usage='accept')
                s_token = gss_srv_ctxt.step(c_token)
                gss_ctxt_status = gss_srv_ctxt.complete
                self.assertNotEqual(None, s_token)
                self.assertEqual(True, gss_ctxt_status)
                # Establish the client context
                c_token = gss_ctxt.step(s_token)
                self.assertEqual(None, c_token)
            else:
                while not gss_ctxt.complete:
                    c_token = gss_ctxt.step(c_token)
                self.assertNotEqual(None, c_token)
            # Build MIC
            mic_token = gss_ctxt.get_signature(mic_msg)

            if self.server_mode:
                # Check MIC
                status = gss_srv_ctxt.verify_signature(mic_msg, mic_token)
                self.assertEqual(0, status)

        else:
            gss_flags = (
                sspicon.ISC_REQ_INTEGRITY |
                sspicon.ISC_REQ_MUTUAL_AUTH |
                sspicon.ISC_REQ_DELEGATE
            )
            # Initialize a GSS-API context.
            target_name = "host/" + socket.getfqdn(self.targ_name)
            gss_ctxt = sspi.ClientAuth("Kerberos",
                                       scflags=gss_flags,
                                       targetspn=target_name)
            if self.server_mode:
                error, token = gss_ctxt.authorize(c_token)
                c_token = token[0].Buffer
                self.assertEqual(0, error)
                # Accept a GSS-API context.
                gss_srv_ctxt = sspi.ServerAuth("Kerberos", spn=target_name)
                error, token = gss_srv_ctxt.authorize(c_token)
                s_token = token[0].Buffer
                # Establish the context.
                error, token = gss_ctxt.authorize(s_token)
                c_token = token[0].Buffer
                self.assertEqual(None, c_token)
                self.assertEqual(0, error)
                # Build MIC
                mic_token = gss_ctxt.sign(mic_msg)
                # Check MIC
                gss_srv_ctxt.verify(mic_msg, mic_token)
            else:
                error, token = gss_ctxt.authorize(c_token)
                c_token = token[0].Buffer
                self.assertNotEqual(0, error)

    def test_gssapi_sspi_client(self):
        """
        Test the used methods of python-gssapi or sspi, sspicon from pywin32.
        """
        self._gssapi_sspi_test()

    def test_gssapi_sspi_server(self):
        """
        Test the used methods of python-gssapi or sspi, sspicon from pywin32.
        """
        self.server_mode = True
        self._gssapi_sspi_test()
