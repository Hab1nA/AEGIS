import tempfile
import unittest
from pathlib import Path

from aegis.execution_lock import (
    CampaignAlreadyRunningError,
    CampaignExecutionLock,
)


class CampaignExecutionLockTests(unittest.TestCase):
    def test_live_owner_rejects_second_controller_and_release_allows_takeover(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_path = Path(directory) / "events.sqlite3"
            owner = CampaignExecutionLock(data_path, "campaign")
            contender = CampaignExecutionLock(data_path, "campaign")
            with owner:
                with self.assertRaisesRegex(CampaignAlreadyRunningError, "already running"):
                    with contender:
                        self.fail("contender unexpectedly acquired the execution lock")
            with contender:
                pass

    def test_different_campaigns_do_not_contend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_path = Path(directory) / "events.sqlite3"
            with (
                CampaignExecutionLock(data_path, "campaign-a"),
                CampaignExecutionLock(data_path, "campaign-b"),
            ):
                pass


if __name__ == "__main__":
    unittest.main()
