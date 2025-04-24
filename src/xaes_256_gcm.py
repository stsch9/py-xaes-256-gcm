import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional


class XAES256GCM(object):
    KEY_SIZE = 32
    NONCE_SIZE = 24

    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("Key must be in bytes")

        if len(key) != self.KEY_SIZE:
            raise ValueError(
                "The key must be exactly %s bytes long" % self.KEY_SIZE,
            )

        self._key = key

    def __bytes__(self) -> bytes:
        return self._key

    def _kda(self, n: bytes) -> tuple[bytes, bytes]:
        cipher = Cipher(algorithms.AES(self._key), modes.ECB())
        encryptor = cipher.encryptor()
        l = encryptor.update(b'\x00' * 16) + encryptor.finalize()

        if (int.from_bytes(l) >> 127) == 0:
            k1 = int.from_bytes(l) << 1
            k1 = k1.to_bytes(16, byteorder='big')
        else:
            k1 = int.from_bytes(l) << 1
            k1 = k1.to_bytes(17, byteorder='big')[1:]  # https://realpython.com/python-bitwise-operators/#left-shift
            k1 = bytes(a ^ b for a, b in zip(k1, (b'\x00' * 15 + b'\x87')))

        m1 = b'\x00\x01X\x00' + n[:12]
        m2 = b'\x00\x02X\x00' + n[:12]

        encryptor = cipher.encryptor()
        kx1 = encryptor.update(bytes(a ^ b for a, b in zip(m1, k1))) + encryptor.finalize()

        encryptor = cipher.encryptor()
        kx2 = encryptor.update(bytes(a ^ b for a, b in zip(m2, k1))) + encryptor.finalize()

        return kx1 + kx2, n[12:]

    def encrypt(
            self,
            plaintext: bytes,
            aad: bytes = b"",
            nonce: Optional[bytes] = None
    ) -> tuple[bytes, bytes]:

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        kx, nx = self._kda(nonce)
        aesgcm = AESGCM(kx)
        ct = aesgcm.encrypt(nx, plaintext, aad)
        del kx

        return nonce, ct

    def decrypt(
            self,
            nonce: bytes,
            ct: bytes,
            aad: bytes = b"",
    ) -> bytes:

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        kx, nx = self._kda(nonce)
        aesgcm = AESGCM(kx)
        plaintext = aesgcm.decrypt(nx, ct, aad)

        del kx

        return plaintext

# #key = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
# key = bytes.fromhex("0303030303030303030303030303030303030303030303030303030303030303")
# n = b"ABCDEFGHIJKLMNOPQRSTUVWX"
#
# cipher = Cipher(algorithms.AES(key), modes.ECB())
# encryptor = cipher.encryptor()
# l = encryptor.update(b'\x00' * 16) + encryptor.finalize()
#
# print(l.hex())
#
# if (int.from_bytes(l) >> 127) == 0:
#     k1 = int.from_bytes(l) << 1
#     k1 = k1.to_bytes(16, byteorder='big')
#     print(k1.hex())
# else:
#     k1 = int.from_bytes(l) << 1
#     k1 = k1.to_bytes(17, byteorder='big')[1:] # https://realpython.com/python-bitwise-operators/#left-shift
#     k1 = bytes(a ^ b for a, b in zip(k1, (b'\x00' * 15 + b'\x87')))
#     print(k1.hex())
#
#
# m1 = b'\x00\x01X\x00' + n[:12]
# m2 = b'\x00\x02X\x00' + n[:12]
# print(m1.hex())
#
# encryptor = cipher.encryptor()
# kx1 = encryptor.update(bytes(a ^ b for a, b in zip(m1, k1))) + encryptor.finalize()
#
# encryptor = cipher.encryptor()
# kx2 = encryptor.update(bytes(a ^ b for a, b in zip(m2, k1))) + encryptor.finalize()
#
# kx = kx1 + kx2
# print("K_x")
# print(kx.hex())
#
# nx = n[12:]
# print(nx.hex())
#
# print(int.from_bytes(b"a"))
# a = b"a"
# print(int(a.hex(), 16))
# print(bin(16))
# print(16 >> 6)
#
# print(hex(int("10000111", 2)))
# print(bytes.fromhex("87"))
# print(bytes.fromhex("00015800"))