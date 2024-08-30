import sys
import unittest

sys.path.append("./src")
from crypto.asymmetric import sm2
from crypto.utils.types import asn1_str


class TestSM2(unittest.TestCase):
    def __init__(self, methodName: str = "TestSM2") -> None:
        super().__init__(methodName)
        print(methodName)
        self.sm2 = sm2.SM2()
        self.private_key = 1
        self.public_key = (
            0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
            0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
        )

    def test_sign_with_sm3(self):
        signature = self.sm2.sign_with_sm3(
            b"hello world", self.private_key, self.public_key
        )
        result = self.sm2.verify_with_sm3(
            asn1_str(signature), b"hello world", self.public_key
        )
        self.assertTrue(result)

    def test_sign_with_sm3_ID(self):
        signature = self.sm2.sign_with_sm3(
            b"hello world", self.private_key, self.public_key, "8765432112345678"
        )
        result = self.sm2.verify_with_sm3(
            asn1_str(signature), b"hello world", self.public_key, "8765432112345678"
        )
        self.assertTrue(result)

    def test_sign_with_sm3_fixed_k(self):
        signature = self.sm2.sign_with_sm3(
            b"hello world", self.private_key, self.public_key, "8765432112345678", 0x12
        )
        result = self.sm2.verify_with_sm3(
            asn1_str(signature), b"hello world", self.public_key, "8765432112345678"
        )
        self.assertTrue(result)

    def test_sig_with_random_k(self):
        signature = self.sm2.sign(b"hello world", self.private_key)
        result = self.sm2.verify(asn1_str(signature), b"hello world", self.public_key)
        self.assertTrue(result)

    def test_sign_with_fixed_k(self):
        signature = self.sm2.sign(b"hello world", self.private_key, 0x1234567812345678)
        result = self.sm2.verify(asn1_str(signature), b"hello world", self.public_key)
        self.assertTrue(result)

    def test_encrypt_decrypt(self):
        cipher = self.sm2.encrypt(b"hello world", self.public_key)
        res = self.sm2.decrypt(asn1_str(cipher), self.private_key)
        self.assertEqual(res, b"hello world")
