
from Crypto.Hash import MD5
from message import Message

class PKey (object):
    """
    Base class for public keys.
    """

    def __init__(self, msg=None):
        """
        Create a new instance of this public key type.  If C{msg} is not
        C{None}, the key's public part(s) will be filled in from the
        message.

        @param msg: an optional SSH L{Message} containing a public key of this
        type.
        @type msg: L{Message}
        """
        pass

    def __str__(self):
        """
        Return a string of an SSH L{Message} made up of the public part(s) of
        this key.

        @return: string representation of an SSH key message.
        @rtype: string
        """
        return ''

    def get_name(self):
        """
        Return the name of this private key implementation.

        @return: name of this private key type, in SSH terminology (for
        example, C{"ssh-rsa"}).
        @rtype: string
        """
        return ''

    def get_fingerprint(self):
        """
        Return an MD5 fingerprint of the public part of this key.  Nothing
        secret is revealed.

        @return: a 16-byte string (binary) of the MD5 fingerprint, in SSH
        format.
        @rtype: string
        """
        return MD5.new(str(self)).digest()

    def verify_ssh_sig(self, data, msg):
        """
        Given a blob of data, and an SSH message representing a signature of
        that data, verify that it was signed with this key.

        @param data: the data that was signed.
        @type data: string
        @param msg: an SSH signature message
        @type msg: L{Message}
        @return: C{True} if the signature verifies correctly; C{False}
        otherwise.
        @rtype: boolean
        """
        return False
    
    def sign_ssh_data(self, randpool, data):
        """
        Sign a blob of data with this private key, and return a string
        representing an SSH signature message.

        @bug: It would be cleaner for this method to return a L{Message}
        object, so it would be complementary to L{verify_ssh_sig}.  FIXME.
        
        @param randpool: a secure random number generator.
        @type randpool: L{Crypto.Util.randpool.RandomPool}
        @param data: the data to sign.
        @type data: string
        @return: string representation of an SSH signature message.
        @rtype: string
        """
        return ''
    
    def read_private_key_file(self, filename):
        """
        Read private key contents from a file into this object.

        @param filename: name of the file to read.
        @type filename: string

        @raise IOError: if there was an error reading the file.
        @raise SSHException: if the key file is invalid
        @raise binascii.Error: on base64 decoding error
        """
        pass

    def sign_ssh_session(self, randpool, sid, username):
        """
        Sign an SSH authentication request.

        @bug: Same as L{sign_ssh_data}
        
        @param randpool: a secure random number generator.
        @type randpool: L{Crypto.Util.randpool.RandomPool}
        @param sid: the session ID given by the server
        @type sid: string
        @param username: the username to use in the authentication request
        @type username: string
        @return: string representation of an SSH signature message.
        @rtype: string
        """
