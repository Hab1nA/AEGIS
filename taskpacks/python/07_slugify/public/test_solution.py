import unittest
from solution import slugify
class T(unittest.TestCase):
 def test_basic(self): self.assertEqual(slugify("Hello World"),"hello-world")
