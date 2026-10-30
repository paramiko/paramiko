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
OpenSSH host (and certificate) helpers for PROTOCOL.certkeys.
"""

import fnmatch
import time

from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.util import constant_time_bytes_eq

SSH_CERT_TYPE_HOST = 2


def _read_principals(principals_blob):
    pm = Message(principals_blob)
    principals = []
    while pm.get_remainder():
        principals.append(pm.get_text())
    return principals


def _hostname_variants(trust_name):
    names = [trust_name]
    if trust_name.startswith("[") and "]:" in trust_name:
        host = trust_name[1 : trust_name.index("]")]
        if host not in names:
            names.append(host)
    return names


def _principal_matches(trust_name, principals):
    for candidate in _hostname_variants(trust_name):
        for principal in principals:
            if fnmatch.fnmatch(candidate, principal):
                return True
    return False


def _parse_cert_fields(cert_blob):
    m = Message(cert_blob)
    cert_type_str = m.get_text()
    m.get_string()
    if cert_type_str.startswith("ssh-rsa") or cert_type_str.startswith(
        "rsa-sha2"
    ):
        m.get_mpint()
        m.get_mpint()
    elif cert_type_str.startswith("ssh-ed25519"):
        m.get_string()
    elif cert_type_str.startswith("ecdsa-sha2"):
        m.get_string()
        m.get_string()
    else:
        return None
    m.get_int64()
    cert_type = m.get_int()
    m.get_string()
    principals = _read_principals(m.get_string())
    valid_after = m.get_int64()
    valid_before = m.get_int64()
    m.get_string()
    m.get_string()
    m.get_string()
    sig_key_blob = m.get_string()
    sig_blob = m.get_string()
    sig_field = Message()
    sig_field.add_string(sig_blob)
    sign_end = len(cert_blob) - len(sig_field.asbytes())
    return {
        "cert_type": cert_type,
        "principals": principals,
        "valid_after": valid_after,
        "valid_before": valid_before,
        "sign_data": cert_blob[:sign_end],
        "sig_key_blob": sig_key_blob,
        "sig_blob": sig_blob,
    }


def _cert_time_valid(valid_after, valid_before, now=None):
    if now is None:
        now = int(time.time())
    if valid_after and now < valid_after:
        return False
    if valid_before and now >= valid_before:
        return False
    return True


def _pkey_from_sig_key_blob(sig_key_blob):
    key_type = Message(sig_key_blob).get_text()
    return PKey.from_type_string(key_type, sig_key_blob)


def verify_host_certificate(ca_key, host_key, trust_name):
    """
    Return True if host_key's OpenSSH certificate is signed by ca_key and
    valid for trust_name (hostname or ``[host]:port``).
    """
    blob = getattr(host_key, "public_blob", None)
    if blob is None:
        return False
    parsed = _parse_cert_fields(blob.key_blob)
    if parsed is None:
        return False
    if parsed["cert_type"] != SSH_CERT_TYPE_HOST:
        return False
    if not _cert_time_valid(parsed["valid_after"], parsed["valid_before"]):
        return False
    if not _principal_matches(trust_name, parsed["principals"]):
        return False
    try:
        embedded_ca = _pkey_from_sig_key_blob(parsed["sig_key_blob"])
    except Exception:
        return False
    if not constant_time_bytes_eq(embedded_ca.asbytes(), ca_key.asbytes()):
        return False
    sig_msg = Message(parsed["sig_blob"])
    return ca_key.verify_ssh_sig(parsed["sign_data"], sig_msg)
