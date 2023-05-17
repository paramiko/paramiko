from paramiko import AgentKey


class AgentKey_:
    class fields:
        """
        _fields
        """

        def defaults_to_get_name_and_blob(self):
            # Manually construct a 'failed to get inner_key' obj
            class FallbackAgentKey(AgentKey):
                def __init__(self, name, blob):
                    self.name = name
                    self.blob = blob
                    self.inner_key = None

            key = FallbackAgentKey(name="lol", blob=b"lmao")
            assert key._fields == ["lol", b"lmao"]

        def defers_to_inner_key_when_present(self, keys):
            key = AgentKey(agent=None, blob=keys.pkey.asbytes())
            assert key._fields == keys.pkey._fields
            assert key == keys.pkey
