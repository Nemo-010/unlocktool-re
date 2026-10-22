"""Tests for the payload crypto (programs.bin AES-256-CBC)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import crypto  # noqa: E402


class TestAESPrimitive(unittest.TestCase):
    """FIPS-197 / NIST SP 800-38A known-answer vectors."""

    def test_fips197_aes256_block(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f'
                            '101112131415161718191a1b1c1d1e1f')
        plain = bytes.fromhex('00112233445566778899aabbccddeeff')
        expect = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')
        self.assertEqual(crypto.aes_encrypt_block(key, plain), expect)
        self.assertEqual(crypto.aes_decrypt_block(key, expect), plain)

    def test_sp800_38a_cbc_aes256(self):
        key = bytes.fromhex('603deb1015ca71be2b73aef0857d7781'
                            '1f352c073b6108d72d9810a30914dff4')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'
                              'ae2d8a571e03ac9c9eb76fac45af8e51')
        expect = bytes.fromhex('f58c4c04d6e5f1ba779eabfb5f7bfbd6'
                               '9cfc4e967edb808d679f777bc6702c7d')
        self.assertEqual(crypto.cbc_encrypt(key, iv, plain), expect)
        self.assertEqual(crypto.cbc_decrypt(key, iv, expect), plain)


@unittest.skipUnless(crypto.openssl_available(), 'openssl not installed')
class TestPurePythonMatchesOpenSSL(unittest.TestCase):
    def test_random_roundtrip(self):
        import random
        rng = random.Random(7)
        for _ in range(3):
            key = bytes(rng.randrange(256) for _ in range(32))
            iv = bytes(rng.randrange(256) for _ in range(16))
            data = bytes(rng.randrange(256) for _ in range(160))
            self.assertEqual(crypto.cbc_encrypt(key, iv, data),
                             crypto.cbc_encrypt_fast(key, iv, data))
            self.assertEqual(crypto.cbc_decrypt(key, iv, data),
                             crypto.cbc_decrypt_fast(key, iv, data))


class TestKeyDerivation(unittest.TestCase):
    """The derivation is Rfc2898DeriveBytes(SHA256(password), salt, 1000)."""

    def test_derived_key_vector(self):
        key, iv = crypto.derive(crypto.PASSWORD_RDA)
        self.assertEqual(
            key.hex(),
            '9e90e8509a09b7ed0a724760eca89fab6992bbadd0cabe25cdd1491fa6fab836')
        self.assertEqual(iv.hex(), 'fe16a2cc7ba376bb4fe18855b62cd4ce')

    def test_second_password_vector(self):
        key, iv = crypto.derive(crypto.PASSWORD_RDA_SEC)
        self.assertEqual(
            key.hex(),
            '3c32f480302613afc1c27781c0053e36b2e15a9c6a0a5a1744742882072b0691')
        # the two passwords must not collide
        other, _ = crypto.derive(crypto.PASSWORD_RDA)
        self.assertNotEqual(key, other)

    def test_salt_is_the_shipped_literal(self):
        self.assertEqual(crypto.SALT.hex(), '0000010203040506f1f088102295')
        self.assertEqual(len(crypto.SALT), 14)
        self.assertEqual(crypto.PASSWORD_RDA, b'RDAXTEAM2024')

    def test_sha256_step_matters(self):
        """Without the SHA-256 pre-hash the key is different (README bug)."""
        import hashlib
        wrong = hashlib.pbkdf2_hmac('sha1', crypto.PASSWORD_RDA, crypto.SALT,
                                    crypto.ITERATIONS, 48)
        right, _ = crypto.derive(crypto.PASSWORD_RDA)
        self.assertNotEqual(wrong[:32], right)

    def test_iv_continues_the_same_pbkdf2_stream(self):
        import hashlib
        hashed = hashlib.sha256(crypto.PASSWORD_RDA).digest()
        dk = hashlib.pbkdf2_hmac('sha1', hashed, crypto.SALT, 1000, 48)
        key, iv = crypto.derive(crypto.PASSWORD_RDA)
        self.assertEqual(dk[:32], key)
        self.assertEqual(dk[32:], iv)


class TestPadding(unittest.TestCase):
    def test_pad_strip_roundtrip(self):
        for n in (0, 1, 15, 16, 17, 31, 32):
            data = bytes(range(n))
            self.assertEqual(crypto.pkcs7_strip(crypto.pkcs7_pad(data)), data)

    def test_strip_leaves_bad_padding_alone(self):
        self.assertEqual(crypto.pkcs7_strip(b'abc'), b'abc')

    def test_encrypt_decrypt_roundtrip(self):
        data = b'\x7fELF' + bytes(100)
        blob = crypto.encrypt_programs_bin(data)
        self.assertEqual(len(blob) % 16, 0)
        self.assertEqual(crypto.decrypt_programs_bin(blob), data)


class TestElf(unittest.TestCase):
    def test_is_elf(self):
        self.assertTrue(crypto.is_elf(b'\x7fELF\x02\x01\x01'))
        self.assertFalse(crypto.is_elf(b'MZ\x90\x00'))
        self.assertFalse(crypto.is_elf(b''))


if __name__ == '__main__':
    unittest.main()
