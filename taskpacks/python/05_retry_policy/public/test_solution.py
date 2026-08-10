import unittest
from solution import retry
class TestRetry(unittest.TestCase):
    def test_success(self):
        calls=[]
        def work():
            calls.append(1)
            if len(calls)==1: raise OSError()
            return 7
        self.assertEqual(retry(work,2,OSError),7)
