from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor

from aegis.budget import BudgetManager, OversubscriptionError, ReservationError
from aegis.models import BudgetLimit, UsageRecord


class BudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = BudgetManager("c1", BudgetLimit(100, 50, 20, 10, 10, 30))

    def test_reserve_commit_releases_unused_capacity(self) -> None:
        reservation = self.manager.reserve(UsageRecord("c1", 10, 8, 2, 3, 1, 5))
        during = self.manager.snapshot()
        self.assertEqual(during.reserved.input_tokens, 10)
        actual = UsageRecord("c1", 7, 6, 1, 2, 1, 3, verified=False)
        self.manager.commit(reservation, actual)
        after = self.manager.snapshot()
        self.assertEqual(after.committed.input_tokens, 7)
        self.assertEqual(after.available.input_tokens, 93)
        self.assertEqual(after.open_reservations, 0)
        self.assertFalse(after.usage_verified)
        self.assertEqual(self.manager.committed_records(), (actual,))

    def test_atomic_reservation_rejects_if_any_dimension_exceeds(self) -> None:
        with self.assertRaisesRegex(OversubscriptionError, "requests"):
            self.manager.reserve(UsageRecord("c1", input_tokens=1, requests=11))
        snapshot = self.manager.snapshot()
        self.assertEqual(snapshot.reserved.input_tokens, 0)
        self.assertEqual(snapshot.open_reservations, 0)

    def test_release_and_double_close_are_checked(self) -> None:
        reservation = self.manager.reserve(UsageRecord("c1", requests=1))
        self.manager.release(reservation)
        with self.assertRaises(ReservationError):
            self.manager.release(reservation)
        with self.assertRaises(ValueError):
            self.manager.reserve(UsageRecord("other", requests=1))

    def test_actual_cannot_exceed_reservation(self) -> None:
        reservation = self.manager.reserve(UsageRecord("c1", input_tokens=2, requests=1))
        with self.assertRaisesRegex(ReservationError, "input_tokens"):
            self.manager.commit(reservation, UsageRecord("c1", input_tokens=3, requests=1))
        self.assertEqual(self.manager.snapshot().open_reservations, 1)

    def test_concurrent_reservations_never_oversubscribe(self) -> None:
        manager = BudgetManager("parallel", BudgetLimit(10, 0, 0, 0, 10, 0))

        def attempt(_: int) -> bool:
            try:
                manager.reserve(UsageRecord("parallel", input_tokens=1, requests=1))
                return True
            except OversubscriptionError:
                return False

        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(attempt, range(40)))
        self.assertEqual(sum(outcomes), 10)
        snapshot = manager.snapshot()
        self.assertEqual(snapshot.reserved.input_tokens, 10)
        self.assertEqual(snapshot.available.input_tokens, 0)


if __name__ == "__main__":
    unittest.main()
