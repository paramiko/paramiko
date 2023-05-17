from unittest.mock import Mock

from pytest import mark, raises

from paramiko import AgentKey, Message
from paramiko.agent import (
    SSH2_AGENT_SIGN_RESPONSE,
    SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512,
    cSSH2_AGENTC_SIGN_REQUEST,
)


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

    @mark.parametrize(
        "kwargs,expectation",
        [
            # No algorithm kwarg: no flags (bitfield -> 0 int)
            (dict(), 0),
            (dict(algorithm="rsa-sha2-256"), SSH_AGENT_RSA_SHA2_256),
            (dict(algorithm="rsa-sha2-512"), SSH_AGENT_RSA_SHA2_512),
        ],
    )
    def signing_data(self, kwargs, expectation):
        class FakeAgent:
            def _send_message(self, msg):
                self._sent_message = msg
                sig = Message()
                sig.add_string("lol")
                sig.rewind()
                return SSH2_AGENT_SIGN_RESPONSE, sig

        agent = FakeAgent()
        key = AgentKey(agent, b"secret!!!")
        result = key.sign_ssh_data(b"token", **kwargs)
        assert result == b"lol"
        msg = agent._sent_message
        msg.rewind()
        assert msg.get_byte() == cSSH2_AGENTC_SIGN_REQUEST
        assert msg.get_string() == b"secret!!!"
        assert msg.get_string() == b"token"
        assert msg.get_int() == expectation
