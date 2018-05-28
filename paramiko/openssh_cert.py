import hashlib
import base64
import os

from paramiko.ssh_exception import SSHException
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.rsakey import RSAKey
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key

_extensions = (
    'permit-X11-forwarding',
    'permit-agent-forwarding',
    'permit-port-forwarding',
    'permit-pty',
    'permit-user-rc'
)

OPENSSH_CERT_TYPE_USER = 1
OPENSSH_CERT_TYPE_HOST = 2

# Fully functional OpenSSH Certificates (Signed Keys)
# See PROTOCOL.certkeys docs from OpenSSH
# Similar to public key contents, with additional fields, plus
# a public signing (CA) key and signature.
class Certificate(PKey):
    """
    OpenSSH signed public key (-cert-v01@openssh.com)
    """
    _cert_types = {
        'ssh-rsa-cert-v01@openssh.com': RSAKey,
        'ssh-dss-cert-v01@openssh.com': DSSKey,
        'ecdsa-sha2-nistp256-cert-v01@openssh.com': ECDSAKey,
        'ecdsa-sha2-nistp384-cert-v01@openssh.com': ECDSAKey,
        'ecdsa-sha2-nistp521-cert-v01@openssh.com': ECDSAKey,
        'ssh-ed25519-cert-v01@openssh.com': Ed25519Key
    }

    _signing_key_types = {
        'ssh-rsa': RSAKey,
        'ssh-dss': DSSKey,
        'ecdsa-sha2-nistp256': ECDSAKey,
        'ecdsa-sha2-nistp384': ECDSAKey,
        'ecdsa-sha2-nistp521': ECDSAKey,
        'ssh-ed25519': Ed25519Key
    }

    _critical_options = (
        'force-command',
        'source-address'
    )
    # Having this modifiable for future unit test simplification
    _nonce_bytes = 32

    def __init__(self, msg=None, data=None, comment=''):
        if msg is None:
            msg = Message(data)
        self.blob = msg.asbytes()
        self.key_type = msg.get_text()
        if self.key_type not in self._cert_types:
            raise SSHException('Unknown certificate type: {}'.format(self.key_type))
        self.nonce = msg.get_string()
        self.pubkey = self._cert_types[self.key_type].from_cert_fields(msg)
        # Common v01 certificate fields follow the pubkey data
        self.serial_number = msg.get_int64()
        self.cert_type = msg.get_int()
        self.id_string = msg.get_text()
        # Principals - convert packed list to simple list
        self.principals = []
        principals_list = Message(msg.get_string())
        while principals_list.get_remainder():
            self.principals.append(principals_list.get_string().decode())
        self.valid_after = msg.get_int64()
        self.valid_before = msg.get_int64()
        # Critical options - convert packed structure to dict
        self.options = {}
        opts = Message(msg.get_string())
        while opts.get_remainder():
            option_name = opts.get_text()
            option_value = Message(opts.get_string())
            self.options[option_name] = option_value.get_text()
        # Extensions - convert to simple list
        self.extensions = []
        exts = Message(msg.get_string())
        while exts.get_remainder():
            self.extensions.append(exts.get_text())
            exts.get_string()
        self.reserved = msg.get_string()
        # The signing key can be of any type, so we need to peek
        # inside to know how to construct its key object
        ca = msg.get_string()
        ca_type = Message(ca).get_text()
        if ca_type not in self._signing_key_types:
            raise SSHException('Unknown signing key type: {}'.format(ca_type))
        self.signing_key = self._signing_key_types[ca_type](data=ca)
        # Signing is done on the fields so far
        signed_block = Message(msg.get_so_far()).asbytes()
        self.signature = msg.get_string()
        self.comment = comment

        if msg.get_remainder():
            raise SSHException('Unexpected data at end of certificate')
        if not self.signing_key.verify_ssh_sig(signed_block, Message(self.signature)):
            raise SSHException('Certificate not properly signed')
        # Be backward compatible with earlier minimal work to support certs
        self.public_blob = None
        # Cannot use for signing, yet
        self.private_key = None
        self.comment = comment

    def asbytes(self):
        return self.blob

    def __str__(self):
        # Hash should match value from "ssh-keygen -l" on cert or plain pubkey
        h = hashlib.sha256(self.pubkey.asbytes())
        s = base64.binascii.b2a_base64(h.digest()).decode()
        return self.key_type + ' ' + h.name.upper() + ':' + s.strip().replace('=', '')

    def __hash__(self):
        return hash(self.blob)

    def get_name(self):
        """
        something-cert-v01@openssh.com
        """
        return self.key_type

    def get_bits(self):
        """
        Get the key size of the public (signed) key, not the CA key
        """
        return self.pubkey.get_bits()

    def get_fingerprint(self):
        """
        Get the fingerprint of the public (signed) key, not the CA key
        """
        return self.pubkey.get_fingerprint()

    def associate_private_key(self, private_key):
        """
        In order to sign with certificate, the private key must be loaded
        and associated with the certificate.
        """
        if self.pubkey.asbytes() != private_key.asbytes():
            raise SSHException('Private key does not match certificate')
        self.private_key = private_key

    def can_sign(self):
        return self.private_key is not None

    def sign_ssh_data(self, data):
        if not self.private_key:
            raise SSHException('Certificate requires a private key for signing')
        return self.private_key.sign_ssh_data(data)

    def verify_ssh_sig(self, data, msg):
        """
        Verify with the public key
        """
        return self.pubkey.verify_ssh_sig(data, msg)

    @classmethod
    def load_from_file(cls, filename, load_private=False, passphrase=None):
        """
        Load certificate from xxxxxx-cert.pub (or other file), with
        the option of also loading the corresponding private key, if the
        filename ends with -cert.pub
        """
        with open(filename, 'r') as f:
            for line in f:
                cert_type, encoded_blob, comment = line.split(None, 3)
                if cert_type in cls._cert_types:
                    m = Message(base64.b64decode(encoded_blob))
                    certificate = cls(msg=m, comment=comment or filename)
                    break
            else:
                raise SSHException('Unable to load any certificate from {}'.format(filename))
        if load_private and filename.endswith('-cert.pub'):
            constructor = cls._cert_types[certificate.get_name()].from_private_key_file
            private_key = constructor(filename[:-9], passphrase)
            certificate.associate_private_key(private_key)
        return certificate

    def write_certificate_file(self, filename):
        """
        Write out certificate in pub-key like format:
        <cert_type> <base64 encoded blob> <comment>
        """
        with open(filename, 'w') as f:
            f.write('{} {} {}\n'.format(self.get_name(), self.get_base64(), self.comment))

    # Override from_private_* methods from PKey, since certificates only
    # contain public key components (except for associated private key)
    def from_private_key_file(self, filename, password=None):
        raise Exception('Not implemented in {}'.format(self.__class__.__name__))

    def from_private_key(self, file_obj, password=None):
        raise Exception('Not implemented in {}'.format(self.__class__.__name__))

    @classmethod
    def generate_certificate(cls, pubkey, ca_key, serial=0,
            user_cert=True, id_string='Generated by Paramiko', principals=(),
            valid_after=0, valid_before=18446744073709551615,
            critical_options=None, extensions=_extensions):
        """
        Construct a signed key from a public key, and a (private) CA
        signing key. Additional options can be embedded in the certificate,
        which can be a User certificate (default) or Host certificate.
        Note: The private CA is not included in the certificate data, it
        is used to generate the signature, and the public portion of the CA
        along with the signature are retained.
        """
        cert_name = pubkey.get_name() + '-cert-v01@openssh.com'
        if cert_name not in cls._cert_types:
            raise SSHException('Unsupported certificate type: {}'.format(cert_name))
        m = Message()
        m.add_string(cert_name)
        m.add_string(os.urandom(cls._nonce_bytes))
        # Leverage the pubkey asbytes() to get the component fields
        # which include a prefix name field that we don't need
        components = Message(pubkey.asbytes())
        components.get_string()  # Discard
        m.add_bytes(components.get_remainder())
        m.add_int64(serial)
        if user_cert:
            m.add_int(OPENSSH_CERT_TYPE_USER)
        else:
            m.add_int(OPENSSH_CERT_TYPE_HOST)
            # No supported options or extensions for Host Certificates
            # So override the passed values quietly.
            critical_options = extensions = None
        m.add_string(id_string)
        # Valid Principals is a list of strings packed into its own message
        pm = Message()
        for p in principals:
            pm.add_string(p)
        m.add_string(pm.asbytes())
        m.add_int64(valid_after)
        m.add_int64(valid_before)
        # critical options - packed list of tuples (name, data)
        opts = Message()
        if critical_options:
            for name, data in critical_options.items():
                if name not in cls._critical_options:
                    raise SSHException('Unsupported certificate option: {}'.format(name))
                opts.add_string(name)
                encoded_data = Message()
                encoded_data.add_string(data)
                opts.add_string(encoded_data.asbytes())
        m.add_string(opts.asbytes())
        # extensions
        ext = Message()
        if extensions:
            for x in sorted(extensions):
                ext.add_string(x)
                ext.add_string('')
        m.add_string(ext.asbytes())
        # Reserved field
        m.add_string('')
        # Add the CA Public key, then sign the whole message contents
        m.add_string(ca_key.asbytes())
        sig_blob = m.asbytes()
        signature = ca_key.sign_ssh_data(sig_blob)
        m.add_string(signature)
        # And now that it is bundled and signed, call the constructor
        # to take it all back apart and into a Certificate object
        m.rewind()
        return cls(m)
