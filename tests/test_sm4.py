import sys
import unittest

sys.path.append("./src")
from crypto.symmetric import sm4


class TestSM4(unittest.TestCase):
    def __init__(self, methodName: str = "TestSM4") -> None:
        super().__init__(methodName)
        print(methodName)

    def test_symmetric(self):
        self.assertEqual(
            sm4.symmetric("hello world").hex(),
            "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
        )
        self.assertEqual(
            sm4.symmetric(bytes.fromhex("68656c6c6f20776f726c64")).hex(),
            "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
        )
        self.assertEqual(
            sm4.symmetric(b"hello world").hex(),
            "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
        )
        self.assertEqual(
            sm4.symmetric("test\n").hex(),
            "d583e38313ef3fcecbe58271326ab9e79c951a90d0577be4c2456fc5d1e8ddfc",
        )
        self.assertEqual(
            sm4.symmetric(bytes.fromhex("746573740a")).hex(),
            "d583e38313ef3fcecbe58271326ab9e79c951a90d0577be4c2456fc5d1e8ddfc",
        )
        self.assertEqual(
            sm4.symmetric(b"test\n").hex(),
            "d583e38313ef3fcecbe58271326ab9e79c951a90d0577be4c2456fc5d1e8ddfc",
        )

    def test_error(self):
        self.assertRaises(ValueError, sm4.symmetric, 123)
        self.assertRaises(ValueError, sm4.T_j, -10)
        self.assertRaises(ValueError, sm4.T_j, 64)
        self.assertRaises(ValueError, sm4.FF_j, 1, 2, 3, -10)
        self.assertRaises(ValueError, sm4.FF_j, 1, 2, 3, 64)
        self.assertRaises(ValueError, sm4.GG_j, 1, 2, 3, -10)
        self.assertRaises(ValueError, sm4.GG_j, 1, 2, 3, 64)
