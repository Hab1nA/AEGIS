import unittest
from solution import AtomicCounter
class T(unittest.TestCase):
 def test_increment(self):
  c=AtomicCounter(2); self.assertEqual(c.increment(3),5); self.assertEqual(c.value(),5)
