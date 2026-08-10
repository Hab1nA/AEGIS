import tempfile
import unittest
from pathlib import Path

from aegis.event_store import EventStore
from aegis.reporting import build_report, report_markdown, write_report


class ReportingTests(unittest.TestCase):
    def test_json_and_markdown_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = EventStore(root / "events.db")
            try:
                store.append("c", "state_changed", {"state": "preparing"})
                store.append("c", "usage_committed", {"tokens": 12})
                store.append("c", "quality_locked", {"round": 1, "quality": {"score": 0.8}})
                store.append(
                    "c", "promotion_decided", {"round": 1, "decision": {"promoted": False, "reason": "no"}}
                )
                report = build_report(store, "c")
                self.assertEqual(report["tokens_used"], 12)
                self.assertEqual(report["requests_used"], 1)
                self.assertIn("Quality and promotion", report_markdown(report))
                path = write_report(store, "c", root / "report.md", format="markdown")
                self.assertTrue(path.read_text(encoding="utf-8").startswith("# AEGIS"))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
