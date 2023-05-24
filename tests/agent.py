from unittest.mock import Mock

from pytest import mark, raises

from paramiko import AgentKey, Message, RSAKey
from paramiko.agent import (
    SSH2_AGENT_SIGN_RESPONSE,
    SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512,
    cSSH2_AGENTC_SIGN_REQUEST,
)

from ._util import _support


# AgentKey with no inner_key
class _BareAgentKey(AgentKey):
    def __init__(self, name, blob):
        self.name = name
        self.blob = blob
        self.inner_key = None


class AgentKey_:
    def str_is_repr(self):
        # Tests for a missed spot in Python 3 upgrades: AgentKey.__str__ was
        # returning bytes, as if under Python 2. When bug present, this
        # explodes with "__str__ returned non-string".
        key = AgentKey(None, b"secret!!!")
        assert str(key) == repr(key)

    class init:
        def needs_at_least_two_arguments(self):
            with raises(TypeError):
                AgentKey()
            with raises(TypeError):
                AgentKey(None)

        def sets_attributes_and_parses_blob(self):
            agent = Mock()
            blob = Message()
            blob.add_string("bad-type")
            key = AgentKey(agent=agent, blob=bytes(blob))
            assert key.agent is agent
            assert key.name == "bad-type"
            assert key.blob == bytes(blob)
            assert key.comment == ""  # default
            # TODO: logger testing
            assert key.inner_key is None  # no 'bad-type' algorithm

        def comment_optional(self):
            blob = Message()
            blob.add_string("bad-type")
            key = AgentKey(agent=Mock(), blob=bytes(blob), comment="hi!")
            assert key.comment == "hi!"

        def sets_inner_key_when_known_type(self, keys):
            key = AgentKey(agent=Mock(), blob=bytes(keys.pkey))
            assert key.inner_key == keys.pkey

    class fields:
        def defaults_to_get_name_and_blob(self):
            key = _BareAgentKey(name="lol", blob=b"lmao")
            assert key._fields == ["lol", b"lmao"]

        # TODO: pytest-relaxed is buggy (now?), this shows up under get_bits?
        def defers_to_inner_key_when_present(self, keys):
            key = AgentKey(agent=None, blob=keys.pkey.asbytes())
            assert key._fields == keys.pkey._fields
            assert key == keys.pkey

    class get_bits:
        def defaults_to_superclass_implementation(self):
            # TODO 4.0: assert raises NotImplementedError like changed parent?
            assert _BareAgentKey(None, None).get_bits() == 0

        def defers_to_inner_key_when_present(self, keys):
            key = AgentKey(agent=None, blob=keys.pkey.asbytes())
            assert key.get_bits() == keys.pkey.get_bits()

    class asbytes:
        def defaults_to_owned_blob(self):
            blob = Mock()
            assert _BareAgentKey(name=None, blob=blob).asbytes() is blob

        def defers_to_inner_key_when_present(self, keys):
            key = AgentKey(agent=None, blob=keys.pkey_with_cert.asbytes())
            # Artificially make outer key blob != inner key blob; comment in
            # AgentKey.asbytes implies this can sometimes really happen but I
            # no longer recall when that could be?
            key.blob = b"nope"
            assert key.asbytes() == key.inner_key.asbytes()

    @mark.parametrize(
        "sign_kwargs,expected_flag",
        [
            # No algorithm kwarg: no flags (bitfield -> 0 int)
            (dict(), 0),
            (dict(algorithm="rsa-sha2-256"), SSH_AGENT_RSA_SHA2_256),
            (dict(algorithm="rsa-sha2-512"), SSH_AGENT_RSA_SHA2_512),
            # TODO: ideally we only send these when key is a cert,
            # but it doesn't actually break when not; meh. Really just wants
            # all the parameterization of this test rethought.
            (
                dict(algorithm="rsa-sha2-256-cert-v01@openssh.com"),
                SSH_AGENT_RSA_SHA2_256,
            ),
            (
                dict(algorithm="rsa-sha2-512-cert-v01@openssh.com"),
                SSH_AGENT_RSA_SHA2_512,
            ),
        ],
    )
    def signing_data(self, sign_kwargs, expected_flag):
        class FakeAgent:
            def _send_message(self, msg):
                # The thing we actually care most about, we're not testing
                # ssh-agent itself here
                self._sent_message = msg
                sig = Message()
                sig.add_string("lol")
                sig.rewind()
                return SSH2_AGENT_SIGN_RESPONSE, sig

        for do_cert in (False, True):
            agent = FakeAgent()
            # Get key kinda like how a real agent would give it to us - if
            # cert, it'd be the entire public blob, not just the pubkey. This
            # ensures the code under test sends _just the pubkey part_ back to
            # the agent during signature requests (bug was us sending _the
            # entire cert blob_, which somehow "worked ok" but always got us
            # SHA1)
            # NOTE: using lower level loader to avoid auto-cert-load when
            # testing regular key (agents expose them separately)
            inner_key = RSAKey.from_private_key_file(_support("rsa.key"))
            blobby = inner_key.asbytes()
            # NOTE: expected key blob always wants to be the real key, even
            # when the "key" is a certificate.
            expected_request_key_blob = blobby
            if do_cert:
                inner_key.load_certificate(_support("rsa.key-cert.pub"))
                blobby = inner_key.public_blob.key_blob
            key = AgentKey(agent, blobby)
            result = key.sign_ssh_data(b"data-to-sign", **sign_kwargs)
            assert result == b"lol"
            msg = agent._sent_message
            msg.rewind()
            assert msg.get_byte() == cSSH2_AGENTC_SIGN_REQUEST
            assert msg.get_string() == expected_request_key_blob
            assert msg.get_string() == b"data-to-sign"
            assert msg.get_int() == expected_flag
