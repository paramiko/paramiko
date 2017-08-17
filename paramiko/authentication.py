"""
High-level authentication classes and subroutines.

Intended to house refactored key & auth related logic, used by the rest of the
system.
"""

import binascii

from .dsskey import DSSKey
from .ecdsakey import ECDSAKey
from .ed25519key import Ed25519Key
from .py3compat import b, decodebytes
from .rsakey import RSAKey
from .ssh_exception import UnknownKeyType, InvalidHostKey


KEY_CLASSES = {
    'ssh-rsa': RSAKey,
    'ssh-dss': DSSKey,
    'ssh-ed25519': Ed25519Key,
}
for identifier in ECDSAKey.supported_key_format_identifiers():
    KEY_CLASSES[identifier] = ECDSAKey


# TODO: is this useful for anything besides _host_ keys? User keys will not
# necessarily know the type beforehand and require a more involved process.
def hostkey_from_text(type_, key, source):
    """
    Attempt to instantiate a `PKey` subclass from OpenSSH-formatted text.

    Specifically, expects the caller to have already identified the key type
    (typically by splitting a larger string such as a known_hosts line or
    SSH-format public key file) and to hand in that type plus the key text.

    :param str type_: Key type, e.g. ``'ssh-rsa'``.
    :param str key:
        Key text; ideally bytes but will be normalized if possible (so, may be
        ``str`` or ``unicode`` on Python 2, or ``str`` or ``bytes`` on Python
        3.)
    :param str source:
        The unadulterated source (known_hosts line, key file data, etc) the key
        came from, to be annotated in an `InvalidHostKey` exception if one is
        raised.
    :returns: An instance of some `PKey` subclass such as `RSAKey`.
    :raises: `SSHException` if ``type_`` is unknown.
    :raises: `InvalidHostKey` if decoding the bytes encountered an error.
    """
    try:
        # Normalize to bytes, in case we were given Unicode.
        key_data = decodebytes(b(key))
        try:
            return KEY_CLASSES[type_](data=key_data)
        except KeyError:
            raise UnknownKeyType(type_=type_, key=key)
    except binascii.Error as e:
        raise InvalidHostKey(source, e)
