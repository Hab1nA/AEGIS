import tempfile, unittest
from pathlib import Path
from solution import safe_join
class TestJoin(unittest.TestCase):
    def test_child(self):
        with tempfile.TemporaryDirectory() as d: self.assertEqual(safe_join(d,"a.txt"), Path(d).resolve()/"a.txt")
