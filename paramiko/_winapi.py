"""
Windows API functions implemented as ctypes functions and classes as found
in jaraco.windows (2.10).

If you encounter issues with this module, please consider reporting the issues
in jaraco.windows and asking the author to port the fixes back here.
"""

import ctypes
import ctypes.wintypes
from paramiko.py3compat import u
try:
    import builtins
except ImportError:
    import __builtin__ as builtins

try:
    USHORT = ctypes.wintypes.USHORT
except AttributeError:
    USHORT = ctypes.c_ushort

######################
# jaraco.windows.error

def format_system_message(errno):
    """
    Call FormatMessage with a system error number to retrieve
    the descriptive error message.
    """
    # first some flags used by FormatMessageW
    ALLOCATE_BUFFER = 0x100
    ARGUMENT_ARRAY = 0x2000
    FROM_HMODULE = 0x800
    FROM_STRING = 0x400
    FROM_SYSTEM = 0x1000
    IGNORE_INSERTS = 0x200

    # Let FormatMessageW allocate the buffer (we'll free it below)
    # Also, let it know we want a system error message.
    flags = ALLOCATE_BUFFER | FROM_SYSTEM
    source = None
    message_id = errno
    language_id = 0
    result_buffer = ctypes.wintypes.LPWSTR()
    buffer_size = 0
    arguments = None
    format_bytes = ctypes.windll.kernel32.FormatMessageW(
        flags,
        source,
        message_id,
        language_id,
        ctypes.byref(result_buffer),
        buffer_size,
        arguments,
    )
    # note the following will cause an infinite loop if GetLastError
    #  repeatedly returns an error that cannot be formatted, although
    #  this should not happen.
    handle_nonzero_success(format_bytes)
    message = result_buffer.value
    ctypes.windll.kernel32.LocalFree(result_buffer)
    return message


class WindowsError(builtins.WindowsError):
    "more info about errors at http://msdn.microsoft.com/en-us/library/ms681381(VS.85).aspx"

    def __init__(self, value=None):
        if value is None:
            value = ctypes.windll.kernel32.GetLastError()
        strerror = format_system_message(value)
        super(WindowsError, self).__init__(value, strerror)

    @property
    def message(self):
        return self.strerror

    @property
    def code(self):
        return self.winerror

    def __str__(self):
        return self.message

    def __repr__(self):
        return '{self.__class__.__name__}({self.winerror})'.format(**vars())

def handle_nonzero_success(result):
    if result == 0:
        raise WindowsError()


CreateFileMapping = ctypes.windll.kernel32.CreateFileMappingW
CreateFileMapping.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPWSTR,
]
CreateFileMapping.restype = ctypes.wintypes.HANDLE

MapViewOfFile = ctypes.windll.kernel32.MapViewOfFile
MapViewOfFile.restype = ctypes.wintypes.HANDLE

class MemoryMap(object):
    """
    A memory map object which can have security attributes overridden.
    """
    def __init__(self, name, length, security_attributes=None):
        self.name = name
        self.length = length
        self.security_attributes = security_attributes
        self.pos = 0

    def __enter__(self):
        p_SA = (
            ctypes.byref(self.security_attributes)
            if self.security_attributes else None
        )
        INVALID_HANDLE_VALUE = -1
        PAGE_READWRITE = 0x4
        FILE_MAP_WRITE = 0x2
        filemap = ctypes.windll.kernel32.CreateFileMappingW(
            INVALID_HANDLE_VALUE, p_SA, PAGE_READWRITE, 0, self.length,
            u(self.name))
        handle_nonzero_success(filemap)
        if filemap == INVALID_HANDLE_VALUE:
            raise Exception("Failed to create file mapping")
        self.filemap = filemap
        self.view = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0)
        return self

    def seek(self, pos):
        self.pos = pos

    def write(self, msg):
        n = len(msg)
        if self.pos + n >= self.length:  # A little safety.
            raise ValueError("Refusing to write %d bytes" % n)
        ctypes.windll.kernel32.RtlMoveMemory(self.view + self.pos, msg, n)
        self.pos += n

    def read(self, n):
        """
        Read n bytes from mapped view.
        """
        out = ctypes.create_string_buffer(n)
        ctypes.windll.kernel32.RtlMoveMemory(out, self.view + self.pos, n)
        self.pos += n
        return out.raw

    def __exit__(self, exc_type, exc_val, tb):
        ctypes.windll.kernel32.UnmapViewOfFile(self.view)
        ctypes.windll.kernel32.CloseHandle(self.filemap)

#########################
# jaraco.windows.security

class TokenInformationClass:
    TokenUser = 1

class TOKEN_USER(ctypes.Structure):
    num = 1
    _fields_ = [
        ('SID', ctypes.c_void_p),
        ('ATTRIBUTES', ctypes.wintypes.DWORD),
    ]


class SECURITY_DESCRIPTOR(ctypes.Structure):
    """
    typedef struct _SECURITY_DESCRIPTOR
        {
        UCHAR Revision;
        UCHAR Sbz1;
        SECURITY_DESCRIPTOR_CONTROL Control;
        PSID Owner;
        PSID Group;
        PACL Sacl;
        PACL Dacl;
        }   SECURITY_DESCRIPTOR;
    """
    SECURITY_DESCRIPTOR_CONTROL = USHORT
    REVISION = 1

    _fields_ = [
        ('Revision', ctypes.c_ubyte),
        ('Sbz1', ctypes.c_ubyte),
        ('Control', SECURITY_DESCRIPTOR_CONTROL),
        ('Owner', ctypes.c_void_p),
        ('Group', ctypes.c_void_p),
        ('Sacl', ctypes.c_void_p),
        ('Dacl', ctypes.c_void_p),
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    """
    typedef struct _SECURITY_ATTRIBUTES {
        DWORD  nLength;
        LPVOID lpSecurityDescriptor;
        BOOL   bInheritHandle;
    } SECURITY_ATTRIBUTES;
    """
    _fields_ = [
        ('nLength', ctypes.wintypes.DWORD),
        ('lpSecurityDescriptor', ctypes.c_void_p),
        ('bInheritHandle', ctypes.wintypes.BOOL),
    ]

    def __init__(self, *args, **kwargs):
        super(SECURITY_ATTRIBUTES, self).__init__(*args, **kwargs)
        self.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)

    @property
    def descriptor(self):
        return self._descriptor

    @descriptor.setter
    def descriptor(self, value):
        self._descriptor = value
        self.lpSecurityDescriptor = ctypes.addressof(value)

def GetTokenInformation(token, information_class):
    """
    Given a token, get the token information for it.
    """
    data_size = ctypes.wintypes.DWORD()
    ctypes.windll.advapi32.GetTokenInformation(token, information_class.num,
        0, 0, ctypes.byref(data_size))
    data = ctypes.create_string_buffer(data_size.value)
    handle_nonzero_success(ctypes.windll.advapi32.GetTokenInformation(token,
        information_class.num,
        ctypes.byref(data), ctypes.sizeof(data),
        ctypes.byref(data_size)))
    return ctypes.cast(data, ctypes.POINTER(TOKEN_USER)).contents

class TokenAccess:
    TOKEN_QUERY = 0x8

def OpenProcessToken(proc_handle, access):
    result = ctypes.wintypes.HANDLE()
    proc_handle = ctypes.wintypes.HANDLE(proc_handle)
    handle_nonzero_success(ctypes.windll.advapi32.OpenProcessToken(
        proc_handle, access, ctypes.byref(result)))
    return result

def get_current_user():
    """
    Return a TOKEN_USER for the owner of this process.
    """
    process = OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        TokenAccess.TOKEN_QUERY,
    )
    return GetTokenInformation(process, TOKEN_USER)

def get_security_attributes_for_user(user=None):
    """
    Return a SECURITY_ATTRIBUTES structure with the SID set to the
    specified user (uses current user if none is specified).
    """
    if user is None:
        user = get_current_user()

    assert isinstance(user, TOKEN_USER), "user must be TOKEN_USER instance"

    SD = SECURITY_DESCRIPTOR()
    SA = SECURITY_ATTRIBUTES()
    # by attaching the actual security descriptor, it will be garbage-
    # collected with the security attributes
    SA.descriptor = SD
    SA.bInheritHandle = 1

    ctypes.windll.advapi32.InitializeSecurityDescriptor(ctypes.byref(SD),
        SECURITY_DESCRIPTOR.REVISION)
    ctypes.windll.advapi32.SetSecurityDescriptorOwner(ctypes.byref(SD),
        user.SID, 0)
    return SA
