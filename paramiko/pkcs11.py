from ctypes import (c_void_p, c_ulong, c_int, c_char_p, cast, addressof,
                    sizeof, byref, cdll, Structure)
import subprocess
import os
import errno
from paramiko.ssh_exception import AuthenticationException, SSHException


class PKCS11Exception (SSHException):
    """
    Exception raised by failures in the PKCS11 api or logic errors.
    """
    pass


class PKCS11AuthenticationException (AuthenticationException):
    """
    Exception raised when pkcs11 authentication failed for some reason.
    """
    pass


def pkcs11_get_public_key(keyid="01"):
    """
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

    return str(public_key)


def pkcs11_open_session(pkcs11provider, pkcs11pin, pkcs11keyid="01",
                        pkcs11slot=0, pkcs11publickey=None):
    """
    :param str pkcs11provider: If using PKCS11, this will be the provider
        for the PKCS11 interface. Example: /usr/local/lib/opensc-pkcs11.so.
    :param str pkcs11pin: If using PKCS11, this will be the pin of your
        token or smartcard.
    :param str pkcs11keyid: The keyid to use for the pkcs11 session.
    :param int pkcs11slot: The slot id used for establishing the session.
    :param str pkcs11publickey: If left the default (None), the public key
        will be detected using OpenSC pkcs15-tool. Alternatively you can
        provide it manually using this argument.
    """
    public_key = ""
    session = None

    # Get Public SSH Key
    if pkcs11publickey is None:
        public_key = pkcs11_get_public_key(pkcs11keyid)

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
    if not os.path.isfile(pkcs11provider):
        raise PKCS11Exception("pkcs11provider path is not valid: %s"
                              % pkcs11provider)
    lib = cdll.LoadLibrary(pkcs11provider)
    res = lib.C_Initialize(byref(init_args))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Initialize")

    # Session
    slot = c_ulong(pkcs11slot)  # slot number
    session = c_ulong()
    flags = c_int(6)  # CKF_SERIAL_SESSION (100b), CKF_RW_SESSION(10b)
    res = lib.C_OpenSession(slot, flags, 0, 0, byref(session))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Open Session")

    # Login
    login_type = c_int(1)  # 1=USER PIN
    str_pin = str(pkcs11pin)
    pin = c_char_p(str_pin)
    res = lib.C_Login(session, login_type, pin, len(str_pin))
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
    objid_str = str(pkcs11keyid)
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

    return {"session": session, "public_key": public_key,
            "keyret": keyret, "provider": pkcs11provider}


def pkcs11_close_session(pkcs11session):
    """
    :param str pkcs11session: pkcs11 session obtained
        by calling pkcs11_open_session
    """
    if "provider" not in pkcs11session:
        raise PKCS11Exception("pkcs11 session is missing the provider,\
                               the session is not valid")
    pkcs11provider = pkcs11session["provider"]
    if not os.path.isfile(pkcs11provider):
        raise PKCS11Exception("pkcs11provider path is not valid: %s"
                              % pkcs11provider)
    lib = cdll.LoadLibrary(pkcs11provider)
    # Wrap things up
    res = lib.C_Finalize(c_int(0))
    if res != 0:
        raise PKCS11Exception("PKCS11 Failed to Finalize")
