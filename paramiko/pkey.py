"""
Private key handling.

This module provides classes for handling various types of private keys
(RSA, DSA, ECDSA, Ed25519) and loading them from files or strings.
"""

import base64
import hashlib
import hmac
import os
import warnings
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, BinaryIO, Optional, Tuple, Union

from paramiko import util
from paramiko.ssh_exception import PasswordRequiredException, SSHException

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed25519,
        rsa,
    )


# OpenSSH private key format constants
_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_OPENSSH_CIPHER_NONE = b"none"
_OPENSSH_CIPHER_AES256_CTR = b"aes256-ctr"
_OPENSSH_KDF_NONE = b"none"
_OPENSSH_KDF_BCRYPT = b"bcrypt"


def _unpad_openssh(data: bytes) -> bytes:
    """
    Remove OpenSSH-style padding from decrypted private key data.

    This function uses constant-time comparison to prevent timing attacks.
    """
    if not data:
        raise SSHException("Invalid key: empty data")
    
    padding_length = data[-1]
    if padding_length == 0 or padding_length > len(data):
        raise SSHException("Invalid key: invalid padding length")
    
    # Verify padding in constant time using hmac.compare_digest
    # The expected padding is 1, 2, 3, ..., padding_length
    expected_padding = bytes(range(1, padding_length + 1))
    actual_padding = data[-padding_length:]
    
    if not hmac.compare_digest(expected_padding, actual_padding):
        raise SSHException("Invalid key: invalid padding")
    
    return data[:-padding_length]


def _pad_openssh(data: bytes, block_size: int = 8) -> bytes:
    """
    Add OpenSSH-style padding to private key data.

    The padding consists of bytes 1, 2, 3, ... up to the padding length.
    """
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes(range(1, padding_length + 1))
    return data + padding


class PKey(ABC):
    """
    Abstract base class for private keys.
    """

    # ... rest of the PKey class and subclasses remain unchanged
    # Only the _unpad_openssh function and password handling are modified

    @classmethod
    def from_private_key_file(cls, filename: str, password: Optional[Union[str, bytes]] = None) -> "PKey":
        """
        Load a private key from a file.

        :param str filename: path to the private key file
        :param password: optional password to decrypt the key (str or bytes)
        :return: a PKey subclass instance
        :raises SSHException: if the key cannot be loaded
        """
        with open(filename, "rb") as f:
            return cls.from_private_key(f, password)

    @classmethod
    def from_private_key(cls, file_obj: BinaryIO, password: Optional[Union[str, bytes]] = None) -> "PKey":
        """
        Load a private key from a file-like object.

        :param file_obj: a file-like object containing the private key
        :param password: optional password to decrypt the key (str or bytes)
        :return: a PKey subclass instance
        :raises SSHException: if the key cannot be loaded
        """
        data = file_obj.read()
        return cls.from_private_key_data(data, password)

    @classmethod
    def from_private_key_data(cls, data: bytes, password: Optional[Union[str, bytes]] = None) -> "PKey":
        """
        Load a private key from bytes.

        :param bytes data: the private key data
        :param password: optional password to decrypt the key (str or bytes)
        :return: a PKey subclass instance
        :raises SSHException: if the key cannot be loaded
        """
        # Convert password to bytes if it's a string, for secure handling
        if isinstance(password, str):
            password = password.encode("utf-8")
        
        # Try each key type
        for key_class in (Ed25519Key, ECDSAKey, RSAKey):
            try:
                return key_class._from_private_key_data(data, password)
            except SSHException:
                continue
        
        raise SSHException("Not a valid private key file")

    # ... rest of the file remains unchanged
    # The key loading methods in subclasses (RSAKey, ECDSAKey, Ed25519Key)
    # should be updated to accept bytes for password and zero it after use
