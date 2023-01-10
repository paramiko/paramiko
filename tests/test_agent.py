import unittest

from paramiko.message import Message
from paramiko.agent import (
    SSH2_AGENT_SIGN_RESPONSE,
    cSSH2_AGENTC_SIGN_REQUEST,
    SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512,
    AgentKey,
)
from paramiko.util import b


class ChaosAgent:
    def _send_message(self, msg):
        self._sent_message = msg
        sig = Message()
        sig.add_string(b("lol"))
        sig.rewind()
        return SSH2_AGENT_SIGN_RESPONSE, sig


class AgentTests(unittest.TestCase):
    def _sign_with_agent(self, kwargs, expectation):
        agent = ChaosAgent()
        key = AgentKey(agent, b("secret!!!"))
        result = key.sign_ssh_data(b("token"), **kwargs)
        assert result == b("lol")
        msg = agent._sent_message
        msg.rewind()
        assert msg.get_byte() == cSSH2_AGENTC_SIGN_REQUEST
        assert msg.get_string() == b("secret!!!")
        assert msg.get_string() == b("token")
        assert msg.get_int() == expectation

    def test_agent_signing_defaults_to_0_for_flags_field(self):
        # No algorithm kwarg at all
        self._sign_with_agent(kwargs=dict(), expectation=0)

    def test_agent_signing_is_2_for_SHA256(self):
        self._sign_with_agent(
            kwargs=dict(algorithm="rsa-sha2-256"),
            expectation=SSH_AGENT_RSA_SHA2_256,
        )

    def test_agent_signing_is_2_for_SHA512(self):
        self._sign_with_agent(
            kwargs=dict(algorithm="rsa-sha2-512"),
            expectation=SSH_AGENT_RSA_SHA2_512,
        )
