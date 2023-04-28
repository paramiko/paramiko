from pytest import raises

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from paramiko import PKey, UnknownKeyType, RSAKey

from ._util import _support


class PKey_:
    class from_type_string:
        def loads_from_type_and_bytes(self, keys):
            obj = PKey.from_type_string(keys.full_type, keys.pkey.asbytes())
            assert obj == keys.pkey

    class from_path:
        def loads_from_Path(self, keys):
            obj = PKey.from_path(keys.path)
            assert obj == keys.pkey

        def loads_from_str(self):
            key = PKey.from_path(str(_support("rsa.key")))
            assert isinstance(key, RSAKey)

        def raises_UnknownKeyType_for_unknown_types(self):
            # I.e. a real, becomes a useful object via cryptography.io, key
            # class that we do NOT support. Chose Ed448 randomly as OpenSSH
            # doesn't seem to support it either, going by ssh-keygen...
            keypath = _support("ed448.key")
            with raises(UnknownKeyType) as exc:
                PKey.from_path(keypath)
            assert issubclass(exc.value.key_type, Ed448PrivateKey)
            with open(keypath, "rb") as fd:
                assert exc.value.key_bytes == fd.read()

        def leaves_cryptography_exceptions_untouched(self):
            # a Python file is not a private key!
            with raises(ValueError):
                PKey.from_path(__file__)
