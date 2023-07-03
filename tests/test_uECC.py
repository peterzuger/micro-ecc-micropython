import random
import binascii
import unittest
from hashlib import sha256

import uECC


UINT32_MAX = (2**32) - 1
UINT16_MAX = (2**16) - 1

MESSAGES = [
    b"abc",
    b"",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
]

TEST_COUNT = 100


class KeyTestVector:
    def __init__(self, curve, private_key, public_key, success):
        self.curve = curve
        self.private_key = binascii.unhexlify(private_key)
        self.public_key = binascii.unhexlify(public_key)
        self.success = success


KEY_TEST_VECTORS = [
    KeyTestVector(
        "secp256r1",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        False,
    ),
    KeyTestVector(
        "secp256r1",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        False,
    ),
    KeyTestVector(
        "secp256r1",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC4766997807775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
        True,
    ),
    KeyTestVector(
        "secp256r1",
        "0000000000000000000000000000000000000000000000000000000000000003",
        "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032",
        True,
    ),
    KeyTestVector(
        "secp256r1",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254D",
        "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B0308521F0EA8A4B39CC339E62011A02579D289B103693D0CF11FFAA3BD3DC0E7B12739",
        True,
    ),
    KeyTestVector(
        "secp256r1",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E",
        "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C78CB9BF2B6670082C8B4F931E59B5D1327D54FCAC7B047C265864ED85D82AFCD",
        True,
    ),
    KeyTestVector(
        "secp256r1",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F",
        "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978F888AAEE24712FC0D6C26539608BCF244582521AC3167DD661FB4862DD878C2E",
        False,
    ),
    KeyTestVector(
        "secp256r1",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A",
        False,
    ),
    KeyTestVector(
        "secp256r1",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        False,
    ),
]


def scramble(s):
    idx = random.randint(0, len(s) - 1)

    return s[:idx] + random.getrandbits(8).to_bytes(1, "little") + s[idx + 1 :]


class uECCTest(unittest.TestCase):
    def test_curves(self):
        # uECC.curves()

        curves = uECC.curves()

        self.assertIsInstance(curves, tuple)

        for e in uECC.curves():
            self.assertIsInstance(e, str)

    def test_Curve(self):
        # uECC.Curve(curve)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            self.assertIsInstance(c, uECC.Curve)

    def test_Curve_invalid_string(self):
        # uECC.Curve(curve)

        for curve in ("", "secp") + tuple(x + " " for x in uECC.curves()):
            with self.assertRaises(ValueError) as e:
                c = uECC.Curve(curve)
                # Unknown curve specified: %s

    def test_Curve_invalid_type(self):
        # uECC.Curve(curve)

        for curve in (1, None, uECC.curves):
            with self.assertRaises(TypeError) as e:
                c = uECC.Curve(curve)
                # can't convert '' object to str implicitly

    def test_curve_size(self):
        # uECC.Curve(curve)
        # .curve_size()

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            curve_size = c.curve_size()

            curve_size_should = int(curve[4:7]) / 8

            self.assertIsInstance(curve_size, int)
            self.assertEqual(curve_size, curve_size_should)

    def test_private_key_size(self):
        # uECC.Curve(curve)
        # .private_key_size()

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            key_size = c.private_key_size()

            self.assertIsInstance(key_size, int)
            self.assertTrue(0 <= key_size <= UINT32_MAX)

    def test_public_key_size(self):
        # uECC.Curve(curve)
        # .public_key_size()

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            key_size = c.public_key_size()

            self.assertIsInstance(key_size, int)
            self.assertTrue(0 <= key_size <= UINT32_MAX)

    def test_make_key(self):
        # uECC.Curve(curve)
        # .make_key()

        for curve in uECC.curves():
            c = uECC.Curve(curve)
            public_key_size = c.public_key_size()
            private_key_size = c.private_key_size()

            for _ in range(TEST_COUNT):
                public_key, private_key = c.make_key()

                self.assertIsInstance(public_key, bytes)
                self.assertIsInstance(private_key, bytes)

                self.assertEqual(public_key_size, len(public_key))
                self.assertEqual(private_key_size, len(private_key))

    def test_make_key_inequality(self):
        # uECC.Curve(curve)
        # .make_key()

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for _ in range(TEST_COUNT):
                public_key1, private_key1 = c.make_key()
                public_key2, private_key2 = c.make_key()

                self.assertNotEqual(public_key1, public_key2)
                self.assertNotEqual(private_key1, private_key2)

    def test_shared_secret(self):
        # uECC.Curve(curve)
        # .shared_secret(public_key, private_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)
            curve_size = c.curve_size()

            for _ in range(TEST_COUNT):
                public_key, private_key = c.make_key()

                secret = c.shared_secret(public_key, private_key)

                self.assertIsInstance(secret, bytes)
                self.assertEqual(curve_size, len(secret))

    def test_shared_secret_same_key(self):
        # uECC.Curve(curve)
        # .shared_secret(public_key, private_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for _ in range(TEST_COUNT):
                public_key, private_key = c.make_key()

                secret1 = c.shared_secret(public_key, private_key)
                secret2 = c.shared_secret(public_key, private_key)

                self.assertEqual(secret1, secret2)

    def test_shared_secret_different_key(self):
        # uECC.Curve(curve)
        # .shared_secret(public_key, private_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for _ in range(TEST_COUNT):
                public_key1, private_key1 = c.make_key()
                public_key2, private_key2 = c.make_key()

                secret1 = c.shared_secret(public_key1, private_key1)
                secret2 = c.shared_secret(public_key2, private_key2)

                self.assertNotEqual(secret1, secret2)

    if hasattr(uECC.Curve, "compress"):

        def test_compress(self):
            # uECC.Curve(curve)
            # .compress(public_key)

            for curve in uECC.curves():
                c = uECC.Curve(curve)
                curve_size = c.curve_size()

                for _ in range(TEST_COUNT):
                    public_key, _ = c.make_key()

                    compressed = c.compress(public_key)

                    self.assertIsInstance(compressed, bytes)
                    self.assertEqual(curve_size + 1, len(compressed))

        def test_compress_equality(self):
            # uECC.Curve(curve)
            # .compress(public_key)

            for curve in uECC.curves():
                c = uECC.Curve(curve)

                for _ in range(TEST_COUNT):
                    public_key, _ = c.make_key()

                    compressed1 = c.compress(public_key)
                    compressed2 = c.compress(public_key)

                    self.assertEqual(compressed1, compressed2)

        def test_decompress(self):
            # uECC.Curve(curve)
            # .decompress(public_key)

            for curve in uECC.curves():
                c = uECC.Curve(curve)
                curve_size = c.curve_size()

                for _ in range(TEST_COUNT):
                    public_key, _ = c.make_key()

                    compressed = c.compress(public_key)

                    decompressed = c.decompress(compressed)

                    self.assertIsInstance(decompressed, bytes)
                    self.assertEqual(c.public_key_size(), len(decompressed))
                    self.assertEqual(public_key, decompressed)

    def test_valid_public_key(self):
        # uECC.Curve(curve)
        # .valid_public_key(public_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for _ in range(TEST_COUNT):
                public_key, _ = c.make_key()

                valid = c.valid_public_key(public_key)

                self.assertIsInstance(valid, bool)
                self.assertTrue(valid)

    def test_valid_public_key_invalid(self):
        # uECC.Curve(curve)
        # .valid_public_key(public_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            # test mostly invalid keys
            valid_total = 0
            for _ in range(TEST_COUNT):
                public_key, _ = c.make_key()

                scrambled_public_key = scramble(public_key)

                valid = c.valid_public_key(scrambled_public_key)

                if valid:
                    valid_total += 1

            self.assertLessEqual(valid_total, TEST_COUNT // 10)

    def test_compute_public_key(self):
        # uECC.Curve(curve)
        # .compute_public_key(private_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for _ in range(TEST_COUNT):
                public_key, private_key = c.make_key()

                public_key2 = c.compute_public_key(private_key)

                self.assertIsInstance(public_key2, bytes)
                self.assertEqual(public_key, public_key2)

    def test_compute_public_key_test_vectors(self):
        # uECC.Curve(curve)
        # .compute_public_key(private_key)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

        for vector in KEY_TEST_VECTORS:
            c = uECC.Curve(vector.curve)

            if vector.success:
                public_key = c.compute_public_key(vector.private_key)

                self.assertEqual(public_key, vector.public_key)
            else:
                with self.assertRaises(RuntimeError) as e:
                    public_key = c.compute_public_key(vector.private_key)
                    # uECC_compute_public_key() failed

    def test_sign(self):
        # uECC.Curve(curve)
        # .sign(private_key, message_hash)

        for curve in uECC.curves():
            c = uECC.Curve(curve)
            curve_size = c.curve_size()

            for message in MESSAGES:
                public_key, private_key = c.make_key()

                message_hash = sha256(message).digest()

                signature = c.sign(private_key, message_hash)

                self.assertIsInstance(signature, bytes)
                self.assertEqual(curve_size * 2, len(signature))

    def test_verify(self):
        # uECC.Curve(curve)
        # .verify(public_key, message_hash, signature)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for message in MESSAGES:
                public_key, private_key = c.make_key()

                message_hash = sha256(message).digest()

                signature = c.sign(private_key, message_hash)

                valid = c.verify(public_key, message_hash, signature)

                self.assertIsInstance(valid, bool)
                self.assertTrue(valid)

    def test_verify_invalid_key(self):
        # uECC.Curve(curve)
        # .verify(public_key, message_hash, signature)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for message in MESSAGES:
                public_key, private_key = c.make_key()

                message_hash = sha256(message).digest()

                signature = c.sign(private_key, message_hash)

                scrambled_public_key = scramble(public_key)

                valid = c.verify(scrambled_public_key, message_hash, signature)

                self.assertIsInstance(valid, bool)
                self.assertFalse(valid)

    @unittest.expectedFailure
    def test_verify_invalid_hash(self):
        # uECC.Curve(curve)
        # .verify(public_key, message_hash, signature)

        for curve in uECC.curves():
            c = uECC.Curve(curve)

            for message in MESSAGES:
                public_key, private_key = c.make_key()

                message_hash = sha256(message).digest()

                signature = c.sign(private_key, message_hash)

                scrambled_hash = scramble(message_hash)

                valid = c.verify(public_key, scrambled_hash, signature)

                self.assertIsInstance(valid, bool)
                # TODO: should be false
                self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
