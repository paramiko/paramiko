#!/usr/bin/python

"""
Common API for all public keys.
"""

from Crypto.Hash import MD5
from Crypto.Cipher import DES3
from message import Message
from ssh_exception import SSHException, PasswordRequiredException
import util
import base64

class PKey (object):
    """
    Base class for public keys.
    """

    # known encryption types for private key files:
    _CIPHER_TABLE = {
        'DES-EDE3-CBC': { 'cipher': DES3, 'keysize': 24, 'mode': DES3.MODE_CBC }
    }


    def __init__(self, msg=None, data=None):
        """
        Create a new instance of this public key type.  If C{msg} is given,
        the key's public part(s) will be filled in from the message.  If
        C{data} is given, the key's public part(s) will be filled in from
        the string.

        @param msg: an optional SSH L{Message} containing a public key of this
        type.
        @type msg: L{Message}
        @param data: an optional string containing a public key of this type
        @type data: string
        """
        pass

    def __str__(self):
        """
        Return a string of an SSH L{Message} made up of the public part(s) of
        this key.  This string is suitable for passing to L{__init__} to
        re-create the key object later.

        @return: string representation of an SSH key message.
        @rtype: string
        """
        return ''

    def __cmp__(self, other):
        """
        Compare this key to another.  Returns 0 if this key is equivalent to
        the given key, or non-0 if they are different.  Only the public parts
        of the key are compared, so a public key will compare equal to its
        corresponding private key.

        @param other: key to compare to.
        @type other: L{PKey}
        @return: 0 if the two keys are equivalent, non-0 otherwise.
        @rtype: int
        """
        hs = hash(self)
        ho = hash(other)
        if hs != ho:
            return cmp(hs, ho)
        return cmp(str(self), str(other))

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

    def sign_ssh_data(self, randpool, data):
        """
        Sign a blob of data with this private key, and return a L{Message}
        representing an SSH signature message.

        @param randpool: a secure random number generator.
        @type randpool: L{Crypto.Util.randpool.RandomPool}
        @param data: the data to sign.
        @type data: string
        @return: an SSH signature message.
        @rtype: L{Message}
        """
        return ''

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
    
    def read_private_key_file(self, filename, password=None):
        """
        Read private key contents from a file into this object.  If the private
        key is encrypted and C{password} is not C{None}, the given password
        will be used to decrypt the key (otherwise L{PasswordRequiredException}
        is thrown).

        @param filename: name of the file to read.
        @type filename: string
        @param password: an optional password to use to decrypt the key file,
        if it's encrypted.
        @type password: string

        @raise IOError: if there was an error reading the file.
        @raise PasswordRequiredException: if the private key file is
        encrypted, and C{password} is C{None}.
        @raise SSHException: if the key file is invalid
        @raise binascii.Error: on base64 decoding error
        """
        pass

    def _read_private_key_file(self, tag, filename, password=None):
        """
        Read an SSH2-format private key file, looking for a string of the type
        C{"BEGIN xxx PRIVATE KEY"} for some C{xxx}, base64-decode the text we
        find, and return it as a string.  If the private key is encrypted and
        C{password} is not C{None}, the given password will be used to decrypt
        the key (otherwise L{PasswordRequiredException} is thrown).

        @param tag: C{"RSA"} or C{"DSA"}, the tag used to mark the data block.
        @type tag: string
        @param filename: name of the file to read.
        @type filename: string
        @param password: an optional password to use to decrypt the key file,
        if it's encrypted.
        @type password: string
        @return: data blob that makes up the private key.
        @rtype: string

        @raise IOError: if there was an error reading the file.
        @raise PasswordRequiredException: if the private key file is
        encrypted, and C{password} is C{None}.
        @raise SSHException: if the key file is invalid.
        @raise binascii.Error: on base64 decoding error.
        """
        f = open(filename, 'r')
        lines = f.readlines()
        f.close()
        start = 0
        while (lines[start].strip() != '-----BEGIN ' + tag + ' PRIVATE KEY-----') and (start < len(lines)):
            start += 1
        if start >= len(lines):
            raise SSHException('not a valid ' + tag + ' private key file')
        # parse any headers first
        headers = {}
        start += 1
        while start < len(lines):
            l = lines[start].split(': ')
            if len(l) == 1:
                break
            headers[l[0].lower()] = l[1].strip()
            start += 1
        # find end
        end = start
        while (lines[end].strip() != '-----END ' + tag + ' PRIVATE KEY-----') and (end < len(lines)):
            end += 1
        # if we trudged to the end of the file, just try to cope.
        data = base64.decodestring(''.join(lines[start:end]))
        if not headers.has_key('proc-type'):
            # unencryped: done
            return data
        # encrypted keyfile: will need a password
        if headers['proc-type'] != '4,ENCRYPTED':
            raise SSHException('Unknown private key structure "%s"' % headers['proc-type'])
        try:
            encryption_type, saltstr = headers['dek-info'].split(',')
        except:
            raise SSHException('Can\'t parse DEK-info in private key file')
        if not self._CIPHER_TABLE.has_key(encryption_type):
            raise SSHException('Unknown private key cipher "%s"' % encryption_type)
        # if no password was passed in, raise an exception pointing out that we need one
        if password is None:
            raise PasswordRequiredException('Private key file is encrypted')
        cipher = self._CIPHER_TABLE[encryption_type]['cipher']
        keysize = self._CIPHER_TABLE[encryption_type]['keysize']
        mode = self._CIPHER_TABLE[encryption_type]['mode']
        # this confusing line turns something like '2F91' into '/\x91' (sorry, was feeling clever)
        salt = ''.join([chr(int(saltstr[i:i+2], 16)) for i in range(0, len(saltstr), 2)])
        key = util.generate_key_bytes(MD5, salt, password, keysize)
        return cipher.new(key, mode, salt).decrypt(data)
