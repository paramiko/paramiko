from pytest import raises

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from paramiko import PKey, Ed25519Key, RSAKey, UnknownKeyType, Message

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


    class load_certificate:
        def rsa_public_cert_blobs(self):
            # Data to test signing with (arbitrary)
            data = b"ice weasels"
            # Load key w/o cert at first (so avoiding .from_path)
            key = RSAKey.from_private_key_file(_support("rsa.key"))
            assert key.public_blob is None
            # Sign regular-style (using, arbitrarily, SHA2)
            msg = key.sign_ssh_data(data, "rsa-sha2-256")
            msg.rewind()
            assert "rsa-sha2-256" == msg.get_text()
            signed = msg.get_binary()  # for comparison later

            # Load cert and inspect its internals
            key.load_certificate(_support("rsa.key-cert.pub"))
            assert key.public_blob is not None
            assert key.public_blob.key_type == "ssh-rsa-cert-v01@openssh.com"
            assert key.public_blob.comment == "test_rsa.key.pub"
            msg = Message(key.public_blob.key_blob)
            # cert type
            assert msg.get_text() == "ssh-rsa-cert-v01@openssh.com"
            # nonce
            msg.get_string()
            # public numbers
            assert msg.get_mpint() == key.public_numbers.e
            assert msg.get_mpint() == key.public_numbers.n
            # serial number
            assert msg.get_int64() == 1234
            # TODO: whoever wrote the OG tests didn't care about the remaining
            # fields from
            # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
            # so neither do I, for now...

            # Sign cert-style (still SHA256 - so this actually does almost
            # exactly the same thing under the hood as the previous sign)
            msg = key.sign_ssh_data(data, "rsa-sha2-256-cert-v01@openssh.com")
            msg.rewind()
            assert "rsa-sha2-256" == msg.get_text()
            assert signed == msg.get_binary()  # same signature as above
            msg.rewind()
            assert key.verify_ssh_sig(b"ice weasels", msg)  # our data verified

        def loading_cert_of_different_type_from_key_raises_ValueError(self):
            edkey = Ed25519Key.from_private_key_file(_support("ed25519.key"))
            err = "PublicBlob type ssh-rsa-cert-v01@openssh.com incompatible with key type ssh-ed25519"  # noqa
            with raises(ValueError, match=err):
                edkey.load_certificate(_support("rsa.key-cert.pub"))
