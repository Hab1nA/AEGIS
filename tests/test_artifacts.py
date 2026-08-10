from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aegis.artifacts import (
    ArtifactIntegrityError,
    ArtifactStoreError,
    ContentAddressedArtifactStore,
)


def test_content_addressed_store_is_deterministic_create_only_and_replayable() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = ContentAddressedArtifactStore(Path(directory))
        first = store.put_json("council", {"answer": 42})
        second = store.put_json("council", {"answer": 42})
        assert first == second
        assert store.get(first) == b'{"answer":42}'
        assert len(tuple((Path(directory) / "council").iterdir())) == 1


def test_tampered_bytes_are_detected_on_read_and_reinsert() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = ContentAddressedArtifactStore(Path(directory))
        ref = store.put_bytes("submission", b"trusted frozen bytes")
        target = Path(directory) / "submission" / ref.artifact_id.rsplit(":", 1)[1]
        target.write_bytes(b"tampered")
        with pytest.raises(ArtifactIntegrityError):
            store.get(ref)
        with pytest.raises(ArtifactIntegrityError):
            store.put_bytes("submission", b"trusted frozen bytes")


def test_store_rejects_unsafe_kinds_size_overflow_and_symlink_root() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "artifacts"
        store = ContentAddressedArtifactStore(root, max_artifact_bytes=4)
        with pytest.raises(ValueError):
            store.put_bytes("../escape", b"x")
        with pytest.raises(ArtifactStoreError, match="size"):
            store.put_bytes("task", b"12345")

        link = Path(directory) / "link"
        try:
            link.symlink_to(root, target_is_directory=True)
        except OSError:
            return
        with pytest.raises(ArtifactStoreError, match="real directory"):
            ContentAddressedArtifactStore(link)
