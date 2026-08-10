from __future__ import annotations

import copy

import pytest

from aegis.models import Role
from aegis.roles import GenerationBundle, RoleGeneration


def digest(character: str) -> str:
    return character * 64


def role_generation(role: Role, offset: int) -> RoleGeneration:
    characters = "123456789abcdef"
    return RoleGeneration(
        role=role,
        model_profile_sha256=digest(characters[offset]),
        workflow_artifact_id="sha256:" + digest(characters[offset + 1]),
        subject_artifact_id="sha256:" + digest(characters[offset + 2]),
        runtime_image=f"registry.example/aegis-{role.value}@sha256:{digest(characters[offset + 3])}",
        plugin_artifact_ids=("sha256:" + digest(characters[offset + 4]),),
        budget_policy_sha256=digest(characters[offset + 5]),
    )


def bundle() -> GenerationBundle:
    return GenerationBundle.create(
        parent_generation_id=None,
        controller_abi=1,
        source_commit="a" * 40,
        roles=(
            role_generation(Role.WARRIOR, 0),
            role_generation(Role.JUDGE, 3),
            role_generation(Role.PROSECUTOR, 6),
        ),
        evidence_manifest_sha256="f" * 64,
    )


def test_three_role_bundle_is_content_addressed_and_round_trips() -> None:
    created = bundle()
    assert created.generation_id == "sha256:" + created.compute_digest()
    assert GenerationBundle.from_mapping(created.to_dict()) == created


def test_bundle_rejects_missing_role_and_tampered_identity() -> None:
    created = bundle()
    with pytest.raises(ValueError, match="warrior, judge, and prosecutor"):
        GenerationBundle.create(
            parent_generation_id=None,
            controller_abi=1,
            source_commit="a" * 40,
            roles=created.roles[:2],
            evidence_manifest_sha256="f" * 64,
        )
    raw = copy.deepcopy(created.to_dict())
    raw["source_commit"] = "b" * 40
    with pytest.raises(ValueError, match="does not match"):
        GenerationBundle.from_mapping(raw)


def test_role_generation_rejects_mutable_image_and_noncanonical_plugins() -> None:
    item = role_generation(Role.WARRIOR, 0)
    values = item.to_dict()
    values["runtime_image"] = "registry.example/aegis:latest"
    with pytest.raises(ValueError, match="pinned"):
        RoleGeneration.from_mapping(values)
    values = item.to_dict()
    values["plugin_artifact_ids"] = ["sha256:" + "f" * 64, "sha256:" + "a" * 64]
    with pytest.raises(ValueError, match="canonically sorted"):
        RoleGeneration.from_mapping(values)
