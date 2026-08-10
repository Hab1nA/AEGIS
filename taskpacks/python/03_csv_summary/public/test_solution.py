import unittest
from decimal import Decimal
from solution import sum_amounts
class TestCSV(unittest.TestCase):
    def test_sum(self): self.assertEqual(sum_amounts("name,amount\na,1.20\nb,2.30\n"), Decimal("3.50"))
