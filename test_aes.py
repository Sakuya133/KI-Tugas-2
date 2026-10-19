import unittest

import aes_adapter as aes


class AesTest(unittest.TestCase):
    def test_fips197_block(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        round_keys = aes._expand_key(key)
        self.assertEqual(aes._encrypt_block(plain, round_keys), expected)
        self.assertEqual(aes._decrypt_block(expected, round_keys), plain)

    def test_nist_cbc(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                              "ae2d8a571e03ac9c9eb76fac45af8e51")
        expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d"
                                 "5086cb9b507219ee95db113a917678b2")
        self.assertEqual(aes.cbc_encrypt(plain, key, iv), expected)
        self.assertEqual(aes.cbc_decrypt(expected, key, iv), plain)

    def test_roundtrip_various_lengths(self):
        key = b"kunci-rahasia-16"
        for size in (1, 15, 16, 17, 100, 4096):
            data = bytes(i % 256 for i in range(size))
            iv, cipher = aes.encrypt_message(data, key)
            self.assertEqual(len(cipher) % 16, 0)
            self.assertEqual(aes.decrypt_message(iv, cipher, key), data)

    def test_wrong_key_fails_or_differs(self):
        iv, cipher = aes.encrypt_message(b"halo bob", b"kunci-rahasia-16")
        try:
            result = aes.decrypt_message(iv, cipher, b"kunci-salah-0016")
        except ValueError:
            return
        self.assertNotEqual(result, b"halo bob")


if __name__ == "__main__":
    unittest.main()