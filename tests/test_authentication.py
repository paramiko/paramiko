"""
Tests for paramiko/authentication.py - high level auth logic.
"""

import binascii
import pickle
import unittest

from paramiko import DSSKey, RSAKey, ECDSAKey, Ed25519Key
from paramiko.authentication import KEY_CLASSES, hostkey_from_text
from paramiko.pkey import PKey
from paramiko.py3compat import b, u
from paramiko.ssh_exception import UnknownKeyType, InvalidHostKey

from test_pkey import (
    PUB_DSS, PUB_ECDSA_256, PUB_ECDSA_384, PUB_ECDSA_521, PUB_ED25519, PUB_RSA,
)


class ModuleMembersTest(unittest.TestCase):
    def test_KEY_CLASSES_contains_all_implemented_key_types(self):
        for type_ in """
            ssh-rsa
            ssh-dss
            ecdsa-sha2-nistp256
            ecdsa-sha2-nistp384
            ecdsa-sha2-nistp521
            ssh-ed25519
        """.split():
            err = "{0!r} not found in KEY_CLASSES!".format(type_)
            assert type_ in KEY_CLASSES, err
            err = "{0!r} in KEY_CLASSES wasn't a PKey subclass (was {1})!"
            err = err.format(type_, KEY_CLASSES[type_].__name__)
            assert issubclass(KEY_CLASSES[type_], PKey), err


class hostkey_from_text_Test(unittest.TestCase):
    def _key_type_test(self, transformation):
        type_, key = PUB_RSA.split(' ')
        key = transformation(key)
        result = hostkey_from_text(type_=type_, key=key, source=PUB_RSA)
        assert isinstance(result, RSAKey)

    def test_accepts_unicode(self):
        self._key_type_test(u)

    def test_accepts_bytes(self):
        self._key_type_test(b)

    def test_raises_UnknownKeyType_for_unknown_types(self):
        try:
            hostkey_from_text(type_='lolnope', key='whatever', source='nah')
        except UnknownKeyType as e:
            # Sanity tests around this particular exception class
            assert str(e) == "Unable to handle key of type 'lolnope'"
            assert e.type_ == 'lolnope'
            assert e.key == 'whatever'
            gross = pickle.loads(pickle.dumps(e))
            assert isinstance(gross, UnknownKeyType)
            assert gross.type_ == 'lolnope'
        else:
            assert False, "Did not raise UnknownKeyType for bad key type!"

    def test_raises_InvalidHostKey_when_binascii_errors(self):
        # NOTE: there were apparently zero tests around InvalidHostKey before
        # so I kinda had to guess at how most appropriately to generate one.
        # Simply giving some non-base64-encoded text appears to do the trick!
        try:
            hostkey_from_text(type_='whatevs', key="hi nope", source="engine")
        except InvalidHostKey as e:
            # TODO: maybe rename InvalidHostKey's arg to 'source' in 3.0
            assert e.line == "engine"
            # Not like we -actually- care but it's always one of these for now
            assert isinstance(e.exc, binascii.Error)
        else:
            assert False, "Did not raise InvalidHostKey!"

    def test_functionality_works_for_all_KEY_CLASSES_key_types(self):
        # Mildly tautological, oh well.
        for klass, sample in (
            (RSAKey, PUB_RSA),
            (DSSKey, PUB_DSS),
            (ECDSAKey, PUB_ECDSA_256),
            (ECDSAKey, PUB_ECDSA_384),
            (ECDSAKey, PUB_ECDSA_521),
            (Ed25519Key, PUB_ED25519),
        ):
            type_, key = sample.split(' ')
            result = hostkey_from_text(type_=type_, key=key, source=sample)
            err = "Got {0}, expected {1}!".format(type(result), klass)
            assert isinstance(result, klass), err


# Allow running this test module by its lonesome.
# TODO: just port everything to pytest(-relaxed), ugggh
if __name__ == '__main__':
    unittest.main()
