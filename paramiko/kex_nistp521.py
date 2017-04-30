from hashlib import sha512
from paramiko.kex_nistp256 import KexNistp256
from cryptography.hazmat.primitives.asymmetric import ec


class KexNistp521(KexNistp256):
    name = "ecdh-sha2-nistp521"
    hash_algo = sha512
    curve = ec.SECP521R1()
