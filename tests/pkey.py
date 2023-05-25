from pathlib import Path
from unittest.mock import patch, call

from pytest import raises

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from paramiko import (
    DSSKey,
    ECDSAKey,
    Ed25519Key,
    Message,
    PKey,
    PublicBlob,
    RSAKey,
    UnknownKeyType,
)

from ._util import _support


class PKey_:
    # NOTE: this is incidentally tested by a number of other tests, such as the
    # agent.py test suite
    class from_type_string:
        def loads_from_type_and_bytes(self, keys):
            obj = PKey.from_type_string(keys.full_type, keys.pkey.asbytes())
            assert obj == keys.pkey

        # TODO: exceptions
        #
        # TODO: passphrase? OTOH since this is aimed at the agent...irrelephant

    class from_path:
        def loads_from_Path(self, keys):
            obj = PKey.from_path(keys.path)
            assert obj == keys.pkey

        def loads_from_str(self):
            key = PKey.from_path(str(_support("rsa.key")))
            assert isinstance(key, RSAKey)

        @patch("paramiko.pkey.Path")
        def expands_user(self, mPath):
            # real key for guts that want a real key format
            mykey = Path(_support("rsa.key"))
            pathy = mPath.return_value.expanduser.return_value
            # read_bytes for cryptography.io's loaders
            pathy.read_bytes.return_value = mykey.read_bytes()
            # open() for our own class loader
            pathy.open.return_value = mykey.open()
            # fake out exists() to avoid attempts to load cert
            pathy.exists.return_value = False
            PKey.from_path("whatever")  # we're not testing expanduser itself
            # Both key and cert paths
            mPath.return_value.expanduser.assert_has_calls([call(), call()])

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

        # TODO: passphrase support tested

        class automatically_loads_certificates:
            def existing_cert_loaded_when_given_key_path(self):
                key = PKey.from_path(_support("rsa.key"))
                # Public blob exists despite no .load_certificate call
                assert key.public_blob is not None
                assert (
                    key.public_blob.key_type == "ssh-rsa-cert-v01@openssh.com"
                )
                # And it's definitely the one we expected
                assert key.public_blob == PublicBlob.from_file(
                    _support("rsa.key-cert.pub")
                )

            def can_be_given_cert_path_instead(self):
                key = PKey.from_path(_support("rsa.key-cert.pub"))
                # It's still a key, not a PublicBlob
                assert isinstance(key, RSAKey)
                # Public blob exists despite no .load_certificate call
                assert key.public_blob is not None
                assert (
                    key.public_blob.key_type == "ssh-rsa-cert-v01@openssh.com"
                )
                # And it's definitely the one we expected
                assert key.public_blob == PublicBlob.from_file(
                    _support("rsa.key-cert.pub")
                )

            def no_cert_load_if_no_cert(self):
                # This key exists (it's a copy of the regular one) but has no
                # matching -cert.pub
                key = PKey.from_path(_support("rsa-lonely.key"))
                assert key.public_blob is None

            def excepts_usefully_if_no_key_only_cert(self):
                # TODO: is that truly an error condition? the cert is ~the
                # pubkey and we still require the privkey for signing, yea?
                # This cert exists (it's a copy of the regular one) but there's
                # no rsa-missing.key to load.
                with raises(FileNotFoundError) as info:
                    PKey.from_path(_support("rsa-missing.key-cert.pub"))
                assert info.value.filename.endswith("rsa-missing.key")

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

    def fingerprint(self, keys):
        # NOTE: Hardcoded fingerprint expectation stored in fixture.
        assert keys.pkey.fingerprint == keys.expected_fp

    def algorithm_name(self, keys):
        key = keys.pkey
        if isinstance(key, RSAKey):
            assert key.algorithm_name == "RSA"
        elif isinstance(key, DSSKey):
            assert key.algorithm_name == "DSS"
        elif isinstance(key, ECDSAKey):
            assert key.algorithm_name == "ECDSA"
        elif isinstance(key, Ed25519Key):
            assert key.algorithm_name == "ED25519"
        # TODO: corner case: AgentKey, whose .name can be cert-y (due to the
        # value of the name field passed via agent protocol) and thus
        # algorithm_name is eg "RSA-CERT" - keys loaded directly from disk will
        # never look this way, even if they have a .public_blob attached.

    class equality_and_hashing:
        def same_key_is_equal_to_itself(self, keys):
            assert keys.pkey == keys.pkey2

        def same_key_same_hash(self, keys):
            # NOTE: this isn't a great test due to hashseed randomization under
            # Python 3 preventing use of static values, but it does still prove
            # that __hash__ is implemented/doesn't explode & works across
            # instances
            assert hash(keys.pkey) == hash(keys.pkey2)

        def keys_are_not_equal_to_other_types(self, keys):
            for value in [None, True, ""]:
                assert keys.pkey != value

    class identifiers_classmethods:
        def default_is_class_name_attribute(self):
            # NOTE: not all classes _have_ this, only the ones that don't
            # customize identifiers().
            class MyKey(PKey):
                name = "it me"

            assert MyKey.identifiers() == ["it me"]

        def rsa_is_all_combos_of_cert_and_sha_type(self):
            assert RSAKey.identifiers() == [
                "ssh-rsa",
                "ssh-rsa-cert-v01@openssh.com",
                "rsa-sha2-256",
                "rsa-sha2-256-cert-v01@openssh.com",
                "rsa-sha2-512",
                "rsa-sha2-512-cert-v01@openssh.com",
            ]

        def dss_is_protocol_name(self):
            assert DSSKey.identifiers() == ["ssh-dss"]

        def ed25519_is_protocol_name(self):
            assert Ed25519Key.identifiers() == ["ssh-ed25519"]

        def ecdsa_is_all_curve_names(self):
            assert ECDSAKey.identifiers() == [
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            ]
