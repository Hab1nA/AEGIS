import unittest
from solution import clamp
class TestClamp(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(clamp(3, 0, 2), 2)
        self.assertEqual(clamp(-1, 0, 2), 0)
        self.assertEqual(clamp(1, 0, 2), 1)
