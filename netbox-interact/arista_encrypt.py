#! /usr/bin/env python3

import base64

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_LIB = "cryptography"
except ImportError:
    try:
        from Crypto.Cipher import DES
        _CRYPTO_LIB = "pycryptodome"
    except ImportError:
        raise ImportError("Neither cryptography nor pycryptodome is available")

SEED = b"\xd5\xa8\xc9\x1e\xf5\xd5\x8a\x23"

PARITY_BITS = [
    0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07,
    0x08, 0x08, 0x0b, 0x0b, 0x0d, 0x0d, 0x0e, 0x0e,
    0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
    0x19, 0x19, 0x1a, 0x1a, 0x1c, 0x1c, 0x1f, 0x1f,
    0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26,
    0x29, 0x29, 0x2a, 0x2a, 0x2c, 0x2c, 0x2f, 0x2f,
    0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37,
    0x38, 0x38, 0x3b, 0x3b, 0x3d, 0x3d, 0x3e, 0x3e,
    0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
    0x49, 0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f,
    0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57,
    0x58, 0x58, 0x5b, 0x5b, 0x5d, 0x5d, 0x5e, 0x5e,
    0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67,
    0x68, 0x68, 0x6b, 0x6b, 0x6d, 0x6d, 0x6e, 0x6e,
    0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
    0x79, 0x79, 0x7a, 0x7a, 0x7c, 0x7c, 0x7f, 0x7f
]


def des_setparity(key):
    res = b""
    for b in key:
        pos = b & 0x7f
        res += PARITY_BITS[pos].to_bytes(1, byteorder="big")
    return res


def hashkey(pw):
    result = bytearray(SEED)

    for idx, b in enumerate(pw):
        # result[idx & 7] ^= ord(b)
        result[idx & 7] ^= b


    result = des_setparity(result)

    return bytes(result)


def cbc_encrypt(key: bytes, data: bytes, usebase64=True):
    hashed_key = hashkey(key)
    padding = (8 - ((len(data) + 4) % 8)) % 8
    ciphertext = b"\x4c\x88\xbb" + bytes([padding * 16 + 0xe]) + data + bytes(padding)
    result = None
    if _CRYPTO_LIB == "cryptography":
        cipher = Cipher(algorithms.TripleDES(hashed_key), modes.CBC(bytes(8)), default_backend())
        encryptor = cipher.encryptor()
        result = encryptor.update(ciphertext)
        encryptor.finalize()
    elif _CRYPTO_LIB == "pycryptodome":
        cipher = DES.new(hashed_key, DES.MODE_CBC, bytes(8))
        result = cipher.encrypt(ciphertext)
    else:
        raise Exception("Unknown crypto library")
    if usebase64:
        return base64.b64encode(result)
    else:
        return result
