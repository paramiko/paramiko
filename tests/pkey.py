from paramiko import PKey


class PKey_:
    class from_type_string:
        def loads_from_type_and_bytes(self, key):
            obj = PKey.from_type_string(key.full_type, key.pkey.asbytes())
            assert obj == key.pkey

    class from_path:
        def loads_from_file_path(self, key):
            obj = PKey.from_path(key.path)
            assert obj == key.pkey
