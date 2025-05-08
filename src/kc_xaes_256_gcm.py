import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional


class KCXAES256GCM(object):
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

    def _kda(self, n: bytes) -> tuple[bytes, bytes, bytes]:
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

        return k1, kx1 + kx2, n[12:]

    def _f_com(self, n: bytes, k1: bytes) -> bytes:
        const3 = b'XCMT'
        const4 = b'\x00\x01\x00\x01'
        const5 = b'\x00\x01\x00\x02'

        cipher = Cipher(algorithms.AES(self._key), modes.ECB())
        encryptor = cipher.encryptor()
        x1 = encryptor.update(const3 + n[:12]) + encryptor.finalize()

        w1 = bytes(a ^ b for a, b in zip(x1, n[12:] + const4))
        w1 = bytes(a ^ b for a, b in zip(w1, k1))

        w2 = bytes(a ^ b for a, b in zip(x1, n[12:] + const5))
        w2 = bytes(a ^ b for a, b in zip(w2, k1))

        encryptor = cipher.encryptor()
        kc1 = encryptor.update(w1) + encryptor.finalize()

        encryptor = cipher.encryptor()
        kc2 = encryptor.update(w2) + encryptor.finalize()

        return kc1 + kc2

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

        k1, kx, nx = self._kda(nonce)
        aesgcm = AESGCM(kx)
        ct = aesgcm.encrypt(nx, plaintext, aad)
        del kx

        kc = self._f_com(nonce, k1)

        del k1

        return nonce, ct + kc

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

        k1, kx, nx = self._kda(nonce)
        aesgcm = AESGCM(kx)
        plaintext = aesgcm.decrypt(nx, ct[:-32], aad)

        del kx

        kc = self._f_com(nonce, k1)

        del k1

        if kc != ct[-32:]:
            raise Exception("error: K_C validation failed.")
        else:
            return plaintext