import unittest
from solution import sort_versions
class T(unittest.TestCase):
 def test_numeric(self): self.assertEqual(sort_versions(["1.10","1.2","2.0"]),["1.2","1.10","2.0"])
