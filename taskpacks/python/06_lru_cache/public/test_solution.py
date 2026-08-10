import unittest
from solution import LRUCache
class T(unittest.TestCase):
 def test_evict(self):
  c=LRUCache(2); c.put("a",1); c.put("b",2); c.put("c",3)
  with self.assertRaises(KeyError): c.get("a")
