import sys
import unittest

sys.path.append("./src")
from crypto.symmetric import modes


class TestModes(unittest.TestCase):
    def __init__(self, methodName: str = "TestModes") -> None:
        super().__init__(methodName)
        print(methodName)

    def test_modes(self):
        plaintext1 = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
        key1 = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
        excepted_ciphertext1 = b"\x68\x1e\xdf\x34\xd2\x06\x96\x5e\x86\xb3\xe9\x4f\x53\x6e\x42\x46\x00\x2a\x8a\x4e\xfa\x86\x3c\xca\xd0\x24\xac\x03\x00\xbb\x40\xd2"

        self.assertEqual(
            modes.ecb_encrypt('sm4', plaintext1, key1),
            excepted_ciphertext1,
        )
        self.assertEqual(
            modes.ecb_decrypt('sm4', excepted_ciphertext1, key1),
            plaintext1,
        )

        plaintext2 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        key2 = b'\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef'
        excepted_ciphertext2 = b"\xf7\x66\x67\x8f\x13\xf0\x1a\xde\xac\x1b\x3e\xa9\x55\xad\xb5\x94\xa2\x51\x49\x20\x93\xf8\xf6\x42\x89\xb7\x8d\x6e\x8a\x28\xb1\xc6"

        self.assertEqual(
            modes.ecb_encrypt('sm4', plaintext2, key2),
            excepted_ciphertext2,
        )
        self.assertEqual(
            modes.ecb_decrypt('sm4', excepted_ciphertext2, key2),
            plaintext2,
        )

        plaintext3 = b'hello'
        key3 = b'worldworldworldw'
        excepted_ciphertext3 = b"\x61\xb4\x06\xa9\xb0\x7a\x7e\x6a\x51\x47\xa7\x9e\xe6\x67\x13\xa4"

        self.assertEqual(
            modes.ecb_encrypt('sm4', plaintext3, key3),
            excepted_ciphertext3,
        )
        self.assertEqual(
            modes.ecb_decrypt('sm4', excepted_ciphertext3, key3),
            plaintext3,
        )

        plaintext4 = "你好".encode('utf-8')
        key4 = b'1234567812345678'
        excepted_ciphertext4 = b"\xba\xfd\xd9\xb1\x6d\x6c\x48\x4d\x81\xc9\x78\x5a\x54\xb6\x04\xe1"

        self.assertEqual(
            modes.ecb_encrypt('sm4', plaintext4, key4),
            excepted_ciphertext4,
        )
        self.assertEqual(
            modes.ecb_decrypt('sm4', excepted_ciphertext4, key4),
            plaintext4,
        )
