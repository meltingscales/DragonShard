import unittest
from dragonshard.recon.scanner import run_scan


class TestScanner(unittest.TestCase):
    def test_run_scan(self):
        result = run_scan("127.0.0.1")
        self.assertIn("127.0.0.1", result)
        self.assertIsInstance(result["127.0.0.1"]["tcp"], dict)
        print(result)


if __name__ == '__main__':
    unittest.main()