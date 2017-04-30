from hashlib import sha384
from paramiko.kex_nistp256 import KexNistp256
from cryptography.hazmat.primitives.asymmetric import ec


class KexNistp384(KexNistp256):
    name = "ecdh-sha2-nistp384"
    hash_algo = sha384
    curve = ec.SECP384R1()
