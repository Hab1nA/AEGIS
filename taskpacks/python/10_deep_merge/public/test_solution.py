import unittest
from solution import deep_merge
class T(unittest.TestCase):
 def test_nested(self): self.assertEqual(deep_merge({"a":{"x":1}},{"a":{"y":2}}),{"a":{"x":1,"y":2}})
