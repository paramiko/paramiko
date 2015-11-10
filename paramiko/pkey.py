# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Common API for all public keys.
"""

import base64
from binascii import hexlify, unhexlify
import os
from hashlib import md5

from Crypto.Cipher import DES3, AES

from paramiko import util
from paramiko.common import o600, zero_byte
from paramiko.py3compat import u, encodebytes, decodebytes, b
from paramiko.ssh_exception import SSHException, PasswordRequiredException
from paramiko.ber import BER, BERException
import re
import struct
try:
    import bcrypt   # <-- this has to be py-bcrypt 0.4
    bcrypt_available=True
except ImportError:
    bcrypt_available = False

class PKey (object):
    """
    Base class for public keys.
    """

    # known encryption types for private key files:
    _CIPHER_TABLE = {
        'AES-128-CBC': {'cipher': AES, 'keysize': 16, 'blocksize': 16, 'mode': AES.MODE_CBC},
        'DES-EDE3-CBC': {'cipher': DES3, 'keysize': 24, 'blocksize': 8, 'mode': DES3.MODE_CBC},
    }
    PRIVATE_KEY_FORMAT_ORIGINAL=1
    PRIVATE_KEY_FORMAT_OPENSSH =2

    def __init__(self, msg=None, data=None):
        """
        Create a new instance of this public key type.  If ``msg`` is given,
        the key's public part(s) will be filled in from the message.  If
        ``data`` is given, the key's public part(s) will be filled in from
        the string.

        :param .Message msg:
            an optional SSH `.Message` containing a public key of this type.
        :param str data: an optional string containing a public key of this type

        :raises SSHException:
            if a key cannot be created from the ``data`` or ``msg`` given, or
            no key was passed in.
        """
        pass

    def asbytes(self):
        """
        Return a string of an SSH `.Message` made up of the public part(s) of
        this key.  This string is suitable for passing to `__init__` to
        re-create the key object later.
        """
        return bytes()

    def __str__(self):
        return self.asbytes()

    # noinspection PyUnresolvedReferences
    def __cmp__(self, other):
        """
        Compare this key to another.  Returns 0 if this key is equivalent to
        the given key, or non-0 if they are different.  Only the public parts
        of the key are compared, so a public key will compare equal to its
        corresponding private key.

        :param .Pkey other: key to compare to.
        """
        hs = hash(self)
        ho = hash(other)
        if hs != ho:
            return cmp(hs, ho)
        return cmp(self.asbytes(), other.asbytes())

    def __eq__(self, other):
        return hash(self) == hash(other)

    def get_name(self):
        """
        Return the name of this private key implementation.

        :return:
            name of this private key type, in SSH terminology, as a `str` (for
            example, ``"ssh-rsa"``).
        """
        return ''

    def get_bits(self):
        """
        Return the number of significant bits in this key.  This is useful
        for judging the relative security of a key.

        :return: bits in the key (as an `int`)
        """
        return 0

    def can_sign(self):
        """
        Return ``True`` if this key has the private part necessary for signing
        data.
        """
        return False

    def get_fingerprint(self):
        """
        Return an MD5 fingerprint of the public part of this key.  Nothing
        secret is revealed.

        :return:
            a 16-byte `string <str>` (binary) of the MD5 fingerprint, in SSH
            format.
        """
        return md5(self.asbytes()).digest()

    def get_base64(self):
        """
        Return a base64 string containing the public part of this key.  Nothing
        secret is revealed.  This format is compatible with that used to store
        public key files or recognized host keys.

        :return: a base64 `string <str>` containing the public part of the key.
        """
        return u(encodebytes(self.asbytes())).replace('\n', '')

    def sign_ssh_data(self, data):
        """
        Sign a blob of data with this private key, and return a `.Message`
        representing an SSH signature message.

        :param str data: the data to sign.
        :return: an SSH signature `message <.Message>`.
        """
        return bytes()

    def verify_ssh_sig(self, data, msg):
        """
        Given a blob of data, and an SSH message representing a signature of
        that data, verify that it was signed with this key.

        :param str data: the data that was signed.
        :param .Message msg: an SSH signature message
        :return:
            ``True`` if the signature verifies correctly; ``False`` otherwise.
        """
        return False

    @classmethod
    def from_private_key_file(cls, filename, password=None):
        """
        Create a key object by reading a private key file.  If the private
        key is encrypted and ``password`` is not ``None``, the given password
        will be used to decrypt the key (otherwise `.PasswordRequiredException`
        is thrown).  Through the magic of Python, this factory method will
        exist in all subclasses of PKey (such as `.RSAKey` or `.DSSKey`), but
        is useless on the abstract PKey class.

        :param str filename: name of the file to read
        :param str password:
            an optional password to use to decrypt the key file, if it's
            encrypted
        :return: a new `.PKey` based on the given private key

        :raises IOError: if there was an error reading the file
        :raises PasswordRequiredException: if the private key file is
            encrypted, and ``password`` is ``None``
        :raises SSHException: if the key file is invalid
        """
        key = cls(filename=filename, password=password)
        return key

    @classmethod
    def from_private_key(cls, file_obj, password=None):
        """
        Create a key object by reading a private key from a file (or file-like)
        object.  If the private key is encrypted and ``password`` is not
        ``None``, the given password will be used to decrypt the key (otherwise
        `.PasswordRequiredException` is thrown).

        :param file_obj: the file-like object to read from
        :param str password:
            an optional password to use to decrypt the key, if it's encrypted
        :return: a new `.PKey` based on the given private key

        :raises IOError: if there was an error reading the key
        :raises PasswordRequiredException:
            if the private key file is encrypted, and ``password`` is ``None``
        :raises SSHException: if the key file is invalid
        """
        key = cls(file_obj=file_obj, password=password)
        return key

    def write_private_key_file(self, filename, password=None):
        """
        Write private key contents into a file.  If the password is not
        ``None``, the key is encrypted before writing.

        :param str filename: name of the file to write
        :param str password:
            an optional password to use to encrypt the key file

        :raises IOError: if there was an error writing the file
        :raises SSHException: if the key is invalid
        """
        raise Exception('Not implemented in PKey')

    def write_private_key(self, file_obj, password=None):
        """
        Write private key contents into a file (or file-like) object.  If the
        password is not ``None``, the key is encrypted before writing.

        :param file_obj: the file-like object to write into
        :param str password: an optional password to use to encrypt the key

        :raises IOError: if there was an error writing to the file
        :raises SSHException: if the key is invalid
        """
        raise Exception('Not implemented in PKey')

    def _read_private_key_file(self, tag, filename, password=None):
        """
        Read an SSH2-format private key file, looking for a string of the type
        ``"BEGIN xxx PRIVATE KEY"`` for some ``xxx``, base64-decode the text we
        find, and return it as a string.  If the private key is encrypted and
        ``password`` is not ``None``, the given password will be used to decrypt
        the key (otherwise `.PasswordRequiredException` is thrown).

        :param str tag: ``"RSA"`` or ``"DSA"``, the tag used to mark the data block.
        :param str filename: name of the file to read.
        :param str password:
            an optional password to use to decrypt the key file, if it's
            encrypted.
        :return: data blob (`str`) that makes up the private key.

        :raises IOError: if there was an error reading the file.
        :raises PasswordRequiredException: if the private key file is
            encrypted, and ``password`` is ``None``.
        :raises SSHException: if the key file is invalid.
        """
        with open(filename, 'r') as f:
            data = self._read_private_key(tag, f, password)
        return data

    def _read_private_key(self, tag, f, password=None):
        reBEGINtag = re.compile('^-{5}BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\s*$')
        reENDtag   = re.compile('^-{5}END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\s*$')

        #this block reads the file to find the BEGIN and END tag 
        #determines what type of key it is and passes the found b64 blob to 
        #the respective function
        lines = f.readlines()

        # find the BEGIN tag
        start = 0
        m=reBEGINtag.match(lines[start])
        while (start < len(lines)) and not (m):
            start+=1
            m=reBEGINtag.match(lines[start])
        start += 1

        keytype = m.group(1)
        if start >= len(lines):
            raise SSHException('not a valid private key file')

        # find the END tag
        end = start
        m=reENDtag.match(lines[end])
        while (end < len(lines)) and not (m):
            end+=1
            m=reENDtag.match(lines[end])

        if keytype != 'OPENSSH':
            (pkformat,data)=self._read_private_key_oldformat(lines[start:end],password)
        else:
            (pkformat,data)=self._read_private_key_newformat(''.join(lines[start:end]),password)
        return (pkformat,data)


    def _read_private_key_oldformat(self, lines, password):
        '''
        Read the original OpenSSH SSH2 private ket format 
        '''
        start=0
        # parse any headers first
        headers = {}
        while start < len(lines):
            l = lines[start].split(': ')
            if len(l) == 1:
                break
            headers[l[0].lower()] = l[1].strip()
            start += 1

        try:
            data = decodebytes(b(''.join(lines[start:])))
        except base64.binascii.Error as e:
            raise SSHException('base64 decoding error: ' + str(e))

        if 'proc-type' not in headers:
            # unencryped: done
            return (self.PRIVATE_KEY_FORMAT_ORIGINAL, data)
        # encrypted keyfile: will need a password
        if headers['proc-type'] != '4,ENCRYPTED':
            raise SSHException('Unknown private key structure "%s"' % headers['proc-type'])
        try:
            encryption_type, saltstr = headers['dek-info'].split(',')
        except:
            raise SSHException("Can't parse DEK-info in private key file")
        if encryption_type not in self._CIPHER_TABLE:
            raise SSHException('Unknown private key cipher "%s"' % encryption_type)
        # if no password was passed in, raise an exception pointing out that we need one
        if password is None:
            raise PasswordRequiredException('Private key file is encrypted')
        cipher = self._CIPHER_TABLE[encryption_type]['cipher']
        keysize = self._CIPHER_TABLE[encryption_type]['keysize']
        mode = self._CIPHER_TABLE[encryption_type]['mode']
        salt = unhexlify(b(saltstr))
        key = util.generate_key_bytes(md5, salt, password, keysize)
        return ( self.PRIVATE_KEY_FORMAT_ORIGINAL,
                 cipher.new(key, mode, salt).decrypt(data) )


    def _read_private_key_newformat(self, lines, password):
        try:
            data = decodebytes(b(lines))
        except base64.binascii.Error as e:
            raise SSHException('base64 decoding error: ' + str(e))

        ## read data struct 
        AUTH_MAGIC = data[:14]
        if AUTH_MAGIC != 'openssh-key-v1':
            raise SSHException('Unexpected OpenSSH key header encountered')

        ( cipher,
          kdfname,
          kdf_options,
          num_pubkeys,
          remainder ) = self._uint32_cstruct_unpack(data[15:],'sssur')
        # For now, just support 1 key. Haven't ever seen multiple in the wild. 
        if num_pubkeys>1:
            raise SSHException('Unsupported: private keyfile has multiple keys')
        ( pubkey,
          privkey_blob ) = self._uint32_cstruct_unpack(remainder,'ss')

        if (cipher=='aes256-cbc') and (kdfname=='bcrypt'):
            # Encrypted private key. 
            # The only cipher & kdf used by OpenSSH today are aes256-cbc & bcrypt

            # Check if bcrypt module is available to us
            if not bcrypt_available:
                raise SSHException('bcrypt module not available when attempting '+
                                   'to load encrypted OpenSSH new format key')
            # If no password was passed in, raise an exception pointing 
            # out that we need one
            if password is None:
                raise PasswordRequiredException('Private key file is encrypted')

            # Unpack salt and rounds from kdfoptions
            (salt,
             rounds) = self._uint32_cstruct_unpack(kdf_options,'su')

            # run bcrypt kdf to derive key and iv (32 + 16 bytes)
            key_iv = bcrypt.kdf(password, salt, 48, rounds)
            key=key_iv[:32]
            iv=key_iv[32:]
            # decrypt private key blob
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_privkey=cipher.decrypt(privkey_blob)

        elif (cipher=='none') and (kdfname=='none'):
            # Unencrypted private key
            decrypted_privkey = privkey_blob

        else:
            raise SSHException('Unknown cipher or kdf used in private key file')

        # Unpack private key and verify checkints
        ( checkint1,
          checkint2,
          keytype,
          keydata ) = self._uint32_cstruct_unpack(decrypted_privkey,'uusr')

        if checkint1 != checkint2:
            raise SSHException('OpenSSH private key file checkints do not match')

        # Remove padding
        padlen = ord(keydata[len(keydata)-1])
        keydata=keydata[:len(keydata)-padlen]

        return (self.PRIVATE_KEY_FORMAT_OPENSSH,keydata)


    def _write_private_key_file(self, tag, filename, data, password=None):
        """
        Write an SSH2-format private key file in a form that can be read by
        paramiko or openssh.  If no password is given, the key is written in
        a trivially-encoded format (base64) which is completely insecure.  If
        a password is given, DES-EDE3-CBC is used.

        :param str tag:
            ``"RSA"`` or ``"DSA"``, the tag used to mark the data block.
        :param filename: name of the file to write.
        :param str data: data blob that makes up the private key.
        :param str password: an optional password to use to encrypt the file.

        :raises IOError: if there was an error writing the file.
        """
        with open(filename, 'w', o600) as f:
            # grrr... the mode doesn't always take hold
            os.chmod(filename, o600)
            self._write_private_key(tag, f, data, password)

    def _write_private_key(self, tag, f, data, password=None):
        f.write('-----BEGIN %s PRIVATE KEY-----\n' % tag)
        if password is not None:
            cipher_name = list(self._CIPHER_TABLE.keys())[0]
            cipher = self._CIPHER_TABLE[cipher_name]['cipher']
            keysize = self._CIPHER_TABLE[cipher_name]['keysize']
            blocksize = self._CIPHER_TABLE[cipher_name]['blocksize']
            mode = self._CIPHER_TABLE[cipher_name]['mode']
            salt = os.urandom(blocksize)
            key = util.generate_key_bytes(md5, salt, password, keysize)
            if len(data) % blocksize != 0:
                n = blocksize - len(data) % blocksize
                #data += os.urandom(n)
                # that would make more sense ^, but it confuses openssh.
                data += zero_byte * n
            data = cipher.new(key, mode, salt).encrypt(data)
            f.write('Proc-Type: 4,ENCRYPTED\n')
            f.write('DEK-Info: %s,%s\n' % (cipher_name, u(hexlify(salt)).upper()))
            f.write('\n')
        s = u(encodebytes(data))
        # re-wrap to 64-char lines
        s = ''.join(s.split('\n'))
        s = '\n'.join([s[i: i + 64] for i in range(0, len(s), 64)])
        f.write(s)
        f.write('\n')
        f.write('-----END %s PRIVATE KEY-----\n' % tag)
 
    def _uint32_cstruct_unpack(self,data,strformat):
        '''
        Used to read new OpenSSH private key format.
        Unpacks a c data structure containing a mix of 32-bit uints and 
        variable length strings prefixed by 32-bit uint size field,
        according to the specified format. returns the unpacked vars
        in a tuple.
        Format strings:
          s - denotes a string
          i - denotes a long integer, encoded as a byte string
          u - denotes a 32-bit unsigned integer
          r - the remainder of the input string, returned as a string
        '''
        l=()
        idx=0
        for f in strformat:
            if f=="s":
                #string
                s_size=struct.unpack(">L",data[idx:idx+4])[0]
                idx+=4
                s=data[idx:idx+s_size]
                idx+=s_size
                l = l + (s,)
            if f=="i":
                #long integer
                s_size=struct.unpack(">L",data[idx:idx+4])[0]
                idx+=4
                s=data[idx:idx+s_size]
                idx+=s_size
                i=util.inflate_long(s,True)
                l = l + (i,)
            elif f=="u":
                #32-bit unsigned int
                u=struct.unpack(">L",data[idx:idx+4])[0]
                idx+=4
                l = l + (u,)
            elif f=="r":
                #remainder as string
                s=data[idx:]
                l = l + (s,)
                break
        return l

