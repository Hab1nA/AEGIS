import unittest
from solution import redact
class T(unittest.TestCase):
 def test_password(self): self.assertEqual(redact("password=abc"),"password=[REDACTED]")
