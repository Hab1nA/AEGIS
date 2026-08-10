from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError, replace

from aegis.challenges import (
    ChallengeLimits,
    ChallengeSpec,
    ChallengeVariant,
    FailureCategory,
    SealedTaskMetadata,
    derive_challenges,
)
from aegis.taskpacks.manifest import TaskManifest


def manifest() -> TaskManifest:
    return TaskManifest.from_mapping(
        {
            "task_id": "python-safe-join",
            "version": 1,
            "language": "python",
            "public_dir": "public",
            "hidden_dir": "private-hidden-cases",
            "reference_dir": "private-reference",
            "defect_dir": "defect",
            "mutant_dirs": ["private-mutants/escape"],
            "content_hash": "a" * 64,
        }
    )


def metadata(**overrides: object) -> SealedTaskMetadata:
    values: dict[str, object] = {
        "task_id": "python-safe-join",
        "version": 1,
        "language": "python",
        "content_hash": "a" * 64,
        "base_difficulty": 2,
        "base_cost_units": 100,
        "capability_tags": ("path-safety", "python"),
    }
    values.update(overrides)
    return SealedTaskMetadata(**values)  # type: ignore[arg-type]


class ChallengeTests(unittest.TestCase):
    def test_manifest_projection_does_not_leak_sealed_layout(self) -> None:
        projected = SealedTaskMetadata.from_manifest(
            manifest(),
            base_difficulty=2,
            base_cost_units=100,
            capability_tags=("python", "path-safety"),
        )
        encoded = json.dumps(projected.to_mapping(), sort_keys=True)
        self.assertNotIn("private-hidden", encoded)
        self.assertNotIn("private-reference", encoded)
        self.assertNotIn("private-mutants", encoded)
        self.assertEqual(projected.capability_tags, ("path-safety", "python"))

    def test_derivation_is_deterministic_content_addressed_and_frozen(self) -> None:
        first = derive_challenges(
            metadata(),
            (FailureCategory.SECURITY, FailureCategory.BOUNDARY),
            seed=42,
            count=5,
        )
        second = derive_challenges(metadata(), ("boundary", "security"), seed=42, count=5)
        self.assertEqual(first, second)
        self.assertEqual(len({item.challenge_id for item in first}), 5)
        self.assertTrue(all(item.challenge_id.startswith("challenge-sha256:") for item in first))
        self.assertTrue(
            {item.variant for item in first}
            <= {
                ChallengeVariant.BOUNDARY_MATRIX,
                ChallengeVariant.SECURITY_INVARIANTS,
            }
        )
        with self.assertRaises(FrozenInstanceError):
            first[0].difficulty = 5  # type: ignore[misc]
        with self.assertRaises(ValueError):
            replace(first[0], difficulty=first[0].difficulty + 1)

    def test_seed_changes_variants_but_remains_reproducible(self) -> None:
        one = derive_challenges(metadata(), ("concurrency",), seed=1, count=2)
        two = derive_challenges(metadata(), ("concurrency",), seed=2, count=2)
        self.assertNotEqual(
            tuple(item.challenge_id for item in one),
            tuple(item.challenge_id for item in two),
        )
        self.assertEqual(one, derive_challenges(metadata(), ("concurrency",), seed=1, count=2))

    def test_limits_filter_expensive_variants_and_reject_oversized_base(self) -> None:
        limits = ChallengeLimits(max_difficulty=2, max_cost_units=100)
        specs = derive_challenges(metadata(), tuple(FailureCategory), seed=7, count=4, limits=limits)
        self.assertTrue(all(item.variant is ChallengeVariant.BASELINE_REPLAY for item in specs))
        self.assertTrue(all(item.difficulty <= 2 and item.cost_units <= 100 for item in specs))
        with self.assertRaisesRegex(ValueError, "difficulty"):
            derive_challenges(metadata(base_difficulty=3), (), seed=7, limits=limits)
        with self.assertRaisesRegex(ValueError, "cost"):
            derive_challenges(metadata(base_cost_units=101), (), seed=7, limits=limits)

    def test_maximum_capability_tag_count_remains_valid(self) -> None:
        tags = tuple(sorted(f"capability-{index}" for index in range(24)))
        spec = derive_challenges(metadata(capability_tags=tags), ("security",), seed=3)[0]
        self.assertEqual(spec.capability_tags, tags)

    def test_output_has_no_command_code_path_or_hidden_fields(self) -> None:
        spec = derive_challenges(metadata(), ("security",), seed=9)[0]
        payload = spec.to_mapping()
        forbidden = {"command", "argv", "code", "script", "hidden_tests", "hidden_dir", "path"}
        self.assertFalse(forbidden.intersection(payload))
        self.assertEqual(set(payload), {
            "challenge_id", "schema_version", "base_task_id", "base_task_version",
            "base_content_hash", "language", "variant", "historical_failures", "seed",
            "variant_seed", "difficulty", "cost_units", "capability_tags",
        })

    def test_strict_metadata_history_and_bounds_validation(self) -> None:
        invalid_metadata = (
            {"task_id": "../../escape"},
            {"language": "Python"},
            {"content_hash": "A" * 64},
            {"base_difficulty": 0},
            {"base_cost_units": 10_001},
            {"capability_tags": ()},
            {"capability_tags": ("python", "python")},
            {"capability_tags": ("shell;rm",)},
        )
        for override in invalid_metadata:
            with self.subTest(override=override), self.assertRaises((TypeError, ValueError)):
                metadata(**override)
        with self.assertRaises(ValueError):
            derive_challenges(metadata(), ("hidden-test-case-name",), seed=0)
        with self.assertRaises(ValueError):
            derive_challenges(metadata(), ("security", "security"), seed=0)
        for bad_seed in (-1, 1 << 63, True):
            with self.subTest(seed=bad_seed), self.assertRaises((TypeError, ValueError)):
                derive_challenges(metadata(), (), seed=bad_seed)  # type: ignore[arg-type]
        for bad_count in (0, 17, True):
            with self.subTest(count=bad_count), self.assertRaises((TypeError, ValueError)):
                derive_challenges(metadata(), (), seed=0, count=bad_count)  # type: ignore[arg-type]

    def test_challenge_constructor_rejects_forged_content_id(self) -> None:
        spec = derive_challenges(metadata(), (), seed=0)[0]
        with self.assertRaises(ValueError):
            ChallengeSpec(
                challenge_id="challenge-sha256:" + "0" * 64,
                base_task_id=spec.base_task_id,
                base_task_version=spec.base_task_version,
                base_content_hash=spec.base_content_hash,
                language=spec.language,
                variant=spec.variant,
                historical_failures=spec.historical_failures,
                seed=spec.seed,
                variant_seed=spec.variant_seed,
                difficulty=spec.difficulty,
                cost_units=spec.cost_units,
                capability_tags=spec.capability_tags,
            )


if __name__ == "__main__":
    unittest.main()
