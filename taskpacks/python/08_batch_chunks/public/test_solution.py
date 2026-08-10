import unittest
from solution import batched
class T(unittest.TestCase):
 def test_even(self): self.assertEqual(list(batched(range(4),2)),[[0,1],[2,3]])
