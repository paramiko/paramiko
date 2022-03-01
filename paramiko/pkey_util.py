import base64

from paramiko.pkey import PKey
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException

OPENSSH_AUTH_MAGIC = b"openssh-key-v1\x00"

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
    (b'ssh-dss', 'DSSKey'),
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
provide a way to delay the dispatch to the correct class until the key type is known
"""
def identify_pkey (fpath):
    tag_start = -1
    tag_end = -1
    count = 0
    keytype = None
    lines=''
    with open (fpath, 'r') as f:
        lines = f.read().splitlines()
    try:
        assert lines[0].startswith ("-----BEGIN")
        assert lines[-1].startswith ("-----END")
    except AssertionError as e:
        for line in lines:
            if line.startswith ("-----BEGIN"): tag_start = count
            elif line.startswith ("-----END"): tag_end = count
            count += 1
    else:
        tag_start = 0
        tag_end = len (lines) - 1
    if tag_start < 0 or tag_end < 1: raise SSHException("missing BEGIN or END tag")
    for i in [('DSA', DSSKey), ('EC', ECDSAKey) , ('OPENSSH', None), ('RSA', RSAKey)]:
        if i[0] in lines[tag_start]:
            keytype = i
            break
    if not keytype: SSHException("unknow keytype")
    if keytype[0] == "OPENSSH":
        try:
            buff = bytearray(base64.b64decode("".join(lines[tag_start + 1:tag_end])))
            assert buff[0:len(b'openssh-key-v1')] == b'openssh-key-v1'
            eol=False
            for i in ssh_key_types:
                if eol: break
                lookup = (i[0] + b'\x00')
                for j in range(14, len(buff)):
                    if buff[j:j + len(lookup)] == lookup:
                        keytype = (keytype[0], i[1])
                        eol=True
                        break
        except ValueError as e:
            raise SSHException("not openssh-key-v1")
        except Exception as e:
            raise SSHException from e
    try:
        assert len(keytype) == 2
        assert keytype[1]
        assert issubclass(keytype[1].__class__, PKey)
    except AssertionError as e:
        raise SSHException("pkey_util.identify_pkey error: {} {}".format(keytype, e))
    else:
        return keytype
