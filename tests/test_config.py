import json
import tempfile
import unittest
from pathlib import Path

from aegis.config import AutonomyV2Config, CampaignConfig, ConfigError


def valid_config(**updates):
    value = {
        "campaign_id": "toy",
        "max_rounds": 1,
        "total_tokens": 10_000,
        "max_requests": 10,
        "wall_time_seconds": 60,
        "task_pack_paths": [str((Path.cwd() / "taskpack").resolve())],
        "roles": {
            "warrior": {"model": "w", "budget_share": 0.60, "max_output_tokens": 100},
            "judge": {"model": "j", "budget_share": 0.25, "max_output_tokens": 100},
            "prosecutor": {"model": "p", "budget_share": 0.15, "max_output_tokens": 100},
        },
    }
    value.update(updates)
    return value


class ConfigTests(unittest.TestCase):
    def test_strict_round_trip_and_required_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            config = CampaignConfig.from_mapping(valid_config())
            path = Path(directory) / "campaign.json"
            config.dump(path)
            self.assertEqual(CampaignConfig.load(path), config)
            self.assertNotIn("api_key", path.read_text())

    def test_unknown_missing_and_wrong_share_rejected(self):
        mutations = [
            lambda value: value.update({"api_key": "secret"}),
            lambda value: value.pop("max_rounds"),
            lambda value: value["roles"]["warrior"].update({"budget_share": 0.5}),
            lambda value: value["roles"]["judge"].update({"unknown": True}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = valid_config()
                mutation(value)
                with self.assertRaises(ConfigError):
                    CampaignConfig.from_mapping(value)

    def test_optional_reasoning_effort_is_validated_and_round_trips(self):
        value = valid_config()
        value["roles"]["warrior"]["reasoning_effort"] = "low"
        config = CampaignConfig.from_mapping(value)
        self.assertEqual(config.roles["warrior"].reasoning_effort, "low")
        self.assertEqual(config.to_dict()["roles"]["warrior"]["reasoning_effort"], "low")

        value["roles"]["warrior"]["reasoning_effort"] = "unbounded"
        with self.assertRaisesRegex(ConfigError, "reasoning_effort"):
            CampaignConfig.from_mapping(value)

    def test_production_research_and_fake_sandbox_fail_closed(self):
        with self.assertRaisesRegex(ConfigError, "offline_research"):
            CampaignConfig.from_mapping(valid_config(offline_research=True))
        with self.assertRaisesRegex(ConfigError, "fake sandbox"):
            CampaignConfig.from_mapping(valid_config(sandbox_backend="fake"))
        value = valid_config(
            sandbox_backend="fake", test_mode=True, offline_research=True, research_enabled=False
        )
        self.assertTrue(CampaignConfig.from_mapping(value).test_mode)

    def test_invalid_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps([]))
            with self.assertRaises(ConfigError):
                CampaignConfig.load(path)

    def test_autonomous_evolution_acceptance_profile_is_explicit_and_round_trips(self):
        roles = {
            "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
            "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
            "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
        }
        config = CampaignConfig.from_mapping(
            valid_config(acceptance_profile="autonomous_evolution_v1", roles=roles)
        )
        self.assertEqual(config.acceptance_profile, "autonomous_evolution_v1")
        self.assertEqual(config.to_dict()["acceptance_profile"], "autonomous_evolution_v1")
        with self.assertRaisesRegex(ConfigError, "max_agent_steps"):
            CampaignConfig.from_mapping(
                valid_config(
                    acceptance_profile="autonomous_evolution_v1",
                    max_agent_steps=19,
                    roles=roles,
                )
            )
        undersized = json.loads(json.dumps(roles))
        undersized["warrior"]["max_output_tokens"] = 4095
        with self.assertRaisesRegex(ConfigError, "max_output_tokens"):
            CampaignConfig.from_mapping(
                valid_config(acceptance_profile="autonomous_evolution_v1", roles=undersized)
            )
        with self.assertRaisesRegex(ConfigError, "acceptance_profile"):
            CampaignConfig.from_mapping(valid_config(acceptance_profile="unknown"))

    def test_smoke_only_promotion_flag_round_trips(self):
        config = CampaignConfig.from_mapping(valid_config(evolution_promotion_smoke_only=True))
        self.assertTrue(config.evolution_promotion_smoke_only)
        self.assertTrue(config.to_dict()["evolution_promotion_smoke_only"])
        self.assertFalse(CampaignConfig.from_mapping(valid_config()).evolution_promotion_smoke_only)
        with self.assertRaisesRegex(ConfigError, "evolution_promotion_smoke_only"):
            CampaignConfig.from_mapping(valid_config(evolution_promotion_smoke_only="yes"))

    def test_dynamic_v2_config_is_strict_secret_free_and_has_no_fixed_tasks(self):
        roles = {
            "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
            "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
            "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
        }
        config = CampaignConfig.from_mapping(
            valid_config(
                acceptance_profile="autonomous_evolution_v2",
                roles=roles,
                task_pack_paths=[],
                autonomy_v2={
                    "public_repo_url": "https://github.com/example/aegis-roles.git",
                },
            )
        )
        self.assertIsInstance(config.autonomy_v2, AutonomyV2Config)
        self.assertEqual(config.task_pack_paths, ())
        assert config.autonomy_v2 is not None
        self.assertTrue(config.autonomy_v2.dynamic_only)
        self.assertEqual(CampaignConfig.from_mapping(config.to_dict()), config)

    def test_dynamic_v2_cannot_relax_the_safety_constitution(self):
        roles = {
            "warrior": {"model": "w", "budget_share": 0.55, "max_output_tokens": 4096},
            "judge": {"model": "j", "budget_share": 0.225, "max_output_tokens": 4096},
            "prosecutor": {"model": "p", "budget_share": 0.225, "max_output_tokens": 4096},
        }
        base = valid_config(
            acceptance_profile="autonomous_evolution_v2",
            roles=roles,
            task_pack_paths=[],
        )
        for unsafe in (
            {"builder_block_private_networks": False},
            {"runtime_network": "public"},
            {"external_writes_via_connectors": False},
            {"immutable_safety_constitution": False},
            {"public_repo_url": "https://token@github.com/example/repo.git"},
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(ConfigError):
                CampaignConfig.from_mapping({**base, "autonomy_v2": unsafe})


if __name__ == "__main__":
    unittest.main()
