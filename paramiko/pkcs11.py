"""
Support for PKCS#11-hosted private RSA keys & operations using them.

Smart devices (such as smartcards and YubiKeys) can hold private key data & its
corresponding public key data (in the form of a certificate) as well as perform
signature operations using the private key - all without actually exposing the
private key to the user, and typically protected by a secret PIN as well.

Traditionally, Paramiko expects access to private key material, so the PKCS#11
style of approach requires extra code - in this case, using the `ctypes` stdlib
module to access a PKCS#11 "provider", a ``.so`` or ``.dll`` file such as those
distributed by `OpenSC <https://github.com/OpenSC/OpenSC/wiki>`_.

The typical case involves generating a PKCS "session" (via `.open_session`,
giving it the provider file path and the PIN) and handing the result to
`.client.SSHClient.connect` as its ``pkcs11_session`` argument. The same
session may be used across multiple clients and/or threads; in any case,
it must be explicitly closed via `.close_session`.

.. note::
    This module is based on the following reference material:

    - `OpenSSH's own PKCS#11 support
      <https://github.com/openssh/openssh-portable/blob/master/ssh-pkcs11.c>`_
    - `The official PKCS#11 specification
      <http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html>`_
"""

from ctypes import (
    c_void_p, c_ulong, c_int, c_char_p, cast, addressof, sizeof, byref, cdll,
    Structure,
)
import subprocess
import os
import errno
from paramiko.ssh_exception import AuthenticationException, SSHException


class PKCS11Exception(SSHException):
    """
    Exception raised by failures in the PKCS11 API or related logic errors.
    """
    pass


class PKCS11AuthenticationException(AuthenticationException):
    """
    Exception raised when pkcs11 authentication failed for some reason.
    """
    pass


def get_public_key(keyid="01"):
    """
    Get the public key from a smart device
    :param str pkcs11keyid: The keyid to use for the pkcs11 session.
    """
    public_key = None
    try:
        p = subprocess.Popen(["pkcs15-tool", "--read-ssh-key", keyid],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE)
        out, err = p.communicate()
        if out is not None:
            public_key = out
    except OSError as error:
        if error.errno == errno.ENOENT:
            raise PKCS11Exception("Cannot find pkcs15-tool in PATH.")
        else:
            raise

    if public_key is None or len(public_key) < 1:
        raise PKCS11Exception("Invalid ssh public key returned by pkcs15-tool")

    return public_key.decode('utf-8')


def open_session(provider, pin, keyid="01", slot=0, publickey=None):
    """
    Open a pkcs11 session on a smart device.
    :param str provider: If using PKCS11, this will be the provider
    for the PKCS11 interface. Example: /usr/local/lib/opensc-pkcs11.so.
    :param str pin: If using PKCS11, this will be the pin of your
    token or smartcard.
    :param str keyid: The keyid to use for the pkcs11 session.
    :param int slot: The slot id used for establishing the session.
    :param str publickey: If left the default (None), the public key
    will be detected using OpenSC pkcs15-tool. Alternatively you can
    provide it manually using this argument.
    """
    session = None

    # Get Public SSH Key
    if publickey is None:
        publickey = get_public_key(keyid)

    class ck_c_initialize_args(Structure):
        _fields_ = [('CreateMutex', c_void_p), ('DestroyMutex', c_void_p),
                    ('LockMutex', c_void_p), ('UnlockMutex', c_void_p),
                    ('flags', c_ulong), ('pReserved', c_void_p)]

    # Init Args
    init_args = ck_c_initialize_args()
    init_args.CreateMutex = c_void_p(0)
    init_args.DestroyMutex = c_void_p(0)
    init_args.LockMutex = c_void_p(0)
    init_args.UnlockMutex = c_void_p(0)
    init_args.pReserved = c_void_p(0)
    init_args.flags = c_ulong(2)  # OS Locking for Multithreading Support

    # Init
    if not os.path.isfile(provider):
        raise PKCS11Exception("provider path is not valid: {}".format(provider)) # noqa
    lib = cdll.LoadLibrary(provider)
    res = lib.C_Initialize(byref(init_args))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Initialize")

    # Session
    cstr_slot = c_ulong(slot)  # slot number
    session = c_ulong()
    flags = c_int(6)  # CKF_SERIAL_SESSION (100b), CKF_RW_SESSION(10b)
    res = lib.C_OpenSession(cstr_slot, flags, 0, 0, byref(session))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Open Session")

    # Login
    login_type = c_int(1)  # 1=USER PIN
    str_pin = pin.encode('utf-8')
    cstr_pin = c_char_p(str_pin)
    res = lib.C_Login(session, login_type, cstr_pin, len(str_pin))
    if res != 0:
        raise PKCS11AuthenticationException("PKCS11 Login Failed")

    # Get object for key
    class ck_attribute(Structure):
        _fields_ = [('type', c_ulong), ('value', c_void_p),
                    ('value_len', c_ulong)]

    attrs = (ck_attribute * 3)()
    count = c_ulong()

    # Hard coded, two defined below
    # (attrs is len 2 if using id, if not its len 1)
    nattrs = c_ulong(1)

    keyret = c_ulong()
    cls = c_ulong(3)  # CKO_PRIVATE_KEY
    objid_str = keyid.encode('utf-8')
    objid = c_char_p(objid_str)
    objid_len = c_ulong(len(objid_str))
    attrs[0].type = c_ulong(0)  # CKA_CLASS
    attrs[0].value = cast(addressof(cls), c_void_p)
    attrs[0].value_len = c_ulong(sizeof(cls))
    attrs[1].type = c_ulong(258)  # CKA_ID
    attrs[1].value = cast(objid, c_void_p)
    attrs[1].value_len = objid_len
    res = lib.C_FindObjectsInit(session, attrs, nattrs)
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Find Init")
    res = lib.C_FindObjects(session, byref(keyret), 1, byref(count))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Find Objects")
    res = lib.C_FindObjectsFinal(session)
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Find Objects Final")

    return {"session": session, "public_key": publickey,
            "keyret": keyret, "provider": provider}


def close_session(session):
    """
    Close a pkcs11 session on a smart device.
    :param str session: pkcs11 session obtained
    by calling `.pkcs11.open_session`
    """
    if "provider" not in session:
        raise PKCS11Exception("pkcs11 session is missing the provider, the session is not valid") # noqa
    provider = session["provider"]
    if not os.path.isfile(provider):
        raise PKCS11Exception("provider path is not valid: {}".format(provider)) # noqa
    lib = cdll.LoadLibrary(provider)
    # Wrap things up
    res = lib.C_Finalize(c_int(0))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Finalize")
