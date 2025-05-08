import unittest
from src.kc_xaes_256_gcm import KCXAES256GCM

class TestKCXAES256GCM(unittest.TestCase):
    def test_msb_L_0(self):
        K = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        N = b"ABCDEFGHIJKLMNOPQRSTUVWX"
        Kx = bytes.fromhex("c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b")
        Nx = bytes.fromhex("4d4e4f505152535455565758")
        Plaintext = b"XAES-256-GCM"
        AAD = b""
        Ciphertext = bytes.fromhex("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271")

        kc_xaes = KCXAES256GCM(K)

        #kx, nx = xaes._kda(N)
        #self.assertEqual(kx, Kx)
        #self.assertEqual(nx, Nx)
#
        n, ct = kc_xaes.encrypt(Plaintext, AAD, N)

        pl = kc_xaes.decrypt(n, ct, AAD)
        print(pl)

        #self.assertEqual(n, N)
        #self.assertEqual(ct, Ciphertext)

        #pl = xaes.decrypt(N, Ciphertext, AAD)
        #self.assertEqual(pl, Plaintext)

    #def test_msb_L_1(self):
    #    K = bytes.fromhex("0303030303030303030303030303030303030303030303030303030303030303")
    #    N = b"ABCDEFGHIJKLMNOPQRSTUVWX"
    #    Kx = bytes.fromhex("e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8")
    #    Nx = bytes.fromhex("4d4e4f505152535455565758")
    #    Plaintext = b"XAES-256-GCM"
    #    AAD = b"c2sp.org/XAES-256-GCM"
    #    Ciphertext = bytes.fromhex("986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d")
#
    #    xaes = XAES256GCM(K)
#
    #    kx, nx = xaes._kda(N)
    #    self.assertEqual(kx, Kx)
    #    self.assertEqual(nx, Nx)
#
    #    n, ct = xaes.encrypt(Plaintext, AAD, N)
    #    self.assertEqual(n, N)
    #    self.assertEqual(ct, Ciphertext)
#
    #    pl = xaes.decrypt(N, Ciphertext, AAD)
    #    self.assertEqual(pl, Plaintext)