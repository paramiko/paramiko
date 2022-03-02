import base64

from paramiko.pkey import PKey
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException

OPENSSH_AUTH_MAGIC = b'openssh-key-v1' + b'\x00'

ssh_key_types = [
    (b'ssh-ed25519', Ed25519Key),
    (b'ssh-ed25519-cert-v01@openssh.com', Ed25519Key),
    (b'sk-ssh-ed25519@openssh.com', Ed25519Key),
    (b'sk-ssh-ed25519-cert-v01@openssh.com', Ed25519Key),
    # (b'ssh-xmss@openssh.com', 'XMSS'),
    # (b'ssh-xmss-cert-v01@openssh.com', 'XMSS-CERT'),
    (b'ssh-rsa', RSAKey),
    (b'rsa-sha2-256', RSAKey),
    (b'rsa-sha2-512', RSAKey),
    (b'ssh-dss', DSSKey),
    (b'ecdsa-sha2-nistp256', ECDSAKey),
    (b'ecdsa-sha2-nistp384', ECDSAKey),
    (b'ecdsa-sha2-nistp521', ECDSAKey),
    (b'sk-ecdsa-sha2-nistp256@openssh.com', ECDSAKey),
    (b'webauthn-sk-ecdsa-sha2-nistp256@openssh.com', ECDSAKey),
    (b'ssh-rsa-cert-v01@openssh.com', RSAKey),
    (b'rsa-sha2-256-cert-v01@openssh.com', RSAKey),
    (b'rsa-sha2-512-cert-v01@openssh.com', RSAKey),
    (b'ssh-dss-cert-v01@openssh.com', DSSKey),
    (b'ecdsa-sha2-nistp256-cert-v01@openssh.com', ECDSAKey),
    (b'ecdsa-sha2-nistp384-cert-v01@openssh.com', ECDSAKey),
    (b'ecdsa-sha2-nistp521-cert-v01@openssh.com', ECDSAKey),
    (b'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com', ECDSAKey)
]

"""
determine which class should handle the given key
provide a way to delay the dispatch to the correct class
"""
def identify_pkey(fpath):
    tag_start = -1
    tag_end = -1
    count = 0
    keytype = (None, None)
    lines = ''
    try:
        with open(fpath, 'r') as f:
            lines = f.read().splitlines()
        assert lines
    except Exception:
        raise SSHException("can not determine {}".format(fpath)) from None
    try:
        assert lines[0].startswith("-----BEGIN") or lines[0].startswith(
            "---- BEGIN")
        assert lines[-1].startswith(
            "-----END") or lines[-1].startswith("---- END")
    except AssertionError:
        for line in lines:
            if line.startswith("-----BEGIN") or line.startswith("---- BEGIN"):
                tag_start = count
            elif line.startswith("-----END") or line.startswith("---- END"):
                tag_end = count
            count += 1
    else:
        tag_start = 0
        tag_end = len(lines) - 1

    if tag_start < 0 or tag_end < 1:
        # assume a single line public key
        a,b,u = lines[0].partition(' ')
        for i in ssh_key_types:
            if bytes(a.encode('ascii')) == i[0]:
                keytype = ('SSH2', i[1])
                return keytype

    for i in [('DSA', DSSKey), ('EC', ECDSAKey) , ('OPENSSH', None),
              ('RSA', RSAKey), ('SSH2', None)]:
        if i[0] in lines[tag_start]:
            keytype = i
            break
    if not keytype: raise SSHException("can not determine {}".format(fpath))
    if keytype[0] in ("OPENSSH", "SSH2"):
        try:
            # consume any comment
            for line in lines[tag_start:tag_end]:
                if ':' in line or line.strip() == "":
                    tag_start += 1
                    if line[-1] == '\\':
                        for i in lines[tag_start:tag_end]:
                           if i[-1] == '\\':
                               tag_start += 1

            buff = bytearray(
                base64.b64decode("".join(lines[tag_start + 1:tag_end]))
            )
            if keytype[0] == "OPENSSH":
                assert buff[0:len(OPENSSH_AUTH_MAGIC)] == OPENSSH_AUTH_MAGIC
            eol=False
            for i in ssh_key_types:
                if eol:
                    break
                lookup = (i[0] + b'\x00')
                for j in range(0, len(buff) - len(lookup)):
                    if buff[j:j + len(lookup)] == lookup:
                        keytype = (keytype[0], i[1])
                        eol = True
                        break
        except Exception:
            raise SSHException("can not determine {}".format(fpath))
    try:
        assert len(keytype) == 2
        assert keytype[1]
        assert issubclass(PKey, keytype[1].__bases__)
    except AssertionError:
        raise SSHException(
            "pkey_util.identify_pkey error: {}".format(keytype)
        ) from None
    else:
        return keytype

if __name__ == "__main__":

    import sys
    import os

    if len(sys.argv) > 1 and os.path.isfile(os.path.abspath(sys.argv[1])):
        result = identify_pkey(os.path.abspath(sys.argv[1]))
        print("result: {}".format(result))
    else:
        print("{} /path/to/key".format(sys.argv[0]))
