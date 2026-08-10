import unittest
from solution import TTLCache
class TestCache(unittest.TestCase):
    def test_hit(self):
        now=[0]; c=TTLCache(5, lambda: now[0]); c.put("a", 3); now[0]=4
        self.assertEqual(c.get("a"), 3)
