"""Small immutable content-addressed artifact store used by AEGIS v2."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from aegis.models import canonical_json

_KIND = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_ARTIFACT = re.compile(r"[a-z][a-z0-9-]{0,63}-sha256:[0-9a-f]{64}\Z")


class ArtifactStoreError(RuntimeError):
    pass


class ArtifactIntegrityError(ArtifactStoreError):
    pass


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    kind: str
    artifact_id: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or _KIND.fullmatch(self.kind) is None:
            raise ValueError("kind must be a lowercase artifact kind")
        if not isinstance(self.artifact_id, str) or _ARTIFACT.fullmatch(self.artifact_id) is None:
            raise ValueError("artifact_id must be a typed sha256 content address")
        if not self.artifact_id.startswith(f"{self.kind}-sha256:"):
            raise ValueError("artifact_id kind does not match kind")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise TypeError("size_bytes must be an integer")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")


class ContentAddressedArtifactStore:
    """Create-only store; bytes are verified on every read and existing write."""

    def __init__(self, root: Path, *, max_artifact_bytes: int = 64 * 1024 * 1024) -> None:
        if not isinstance(root, Path):
            raise TypeError("root must be a Path")
        if isinstance(max_artifact_bytes, bool) or not isinstance(max_artifact_bytes, int):
            raise TypeError("max_artifact_bytes must be an integer")
        if max_artifact_bytes <= 0:
            raise ValueError("max_artifact_bytes must be positive")
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise ArtifactStoreError("artifact root must be a real directory")
        self._root = root.resolve(strict=True)
        self._max_artifact_bytes = max_artifact_bytes

    @property
    def root(self) -> Path:
        return self._root

    def put_json(self, kind: str, value: Mapping[str, Any]) -> ArtifactRef:
        if not isinstance(value, Mapping):
            raise TypeError("value must be a mapping")
        return self.put_bytes(kind, canonical_json(value).encode("utf-8"))

    def put_bytes(self, kind: str, payload: bytes) -> ArtifactRef:
        if not isinstance(kind, str) or _KIND.fullmatch(kind) is None:
            raise ValueError("kind must be a lowercase artifact kind")
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > self._max_artifact_bytes:
            raise ArtifactStoreError("artifact exceeds configured size limit")
        digest = hashlib.sha256(payload).hexdigest()
        ref = ArtifactRef(kind, f"{kind}-sha256:{digest}", len(payload))
        directory = self._kind_directory(kind)
        target = directory / digest
        if target.exists():
            self._verify_target(target, ref)
            return ref

        descriptor = (
            os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            if os.name != "nt"
            else None
        )
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, prefix=".staging-", delete=False) as stream:
                temporary_name = stream.name
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary_name, target)
            except FileExistsError:
                pass
            if descriptor is not None:
                os.fsync(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_name is not None:
                Path(temporary_name).unlink(missing_ok=True)
        self._verify_target(target, ref)
        return ref

    def get(self, ref: ArtifactRef) -> bytes:
        if not isinstance(ref, ArtifactRef):
            raise TypeError("ref must be an ArtifactRef")
        target = self._path_for(ref)
        self._verify_target(target, ref)
        try:
            return target.read_bytes()
        except OSError as exc:
            raise ArtifactStoreError("cannot read artifact") from exc

    def _kind_directory(self, kind: str) -> Path:
        directory = self._root / kind
        directory.mkdir(exist_ok=True)
        resolved = directory.resolve(strict=True)
        if resolved.parent != self._root or directory.is_symlink():
            raise ArtifactStoreError("artifact kind directory escaped the store")
        return resolved

    def _path_for(self, ref: ArtifactRef) -> Path:
        digest = ref.artifact_id.rsplit(":", 1)[1]
        directory = self._kind_directory(ref.kind)
        target = directory / digest
        if target.parent != directory:
            raise ArtifactStoreError("artifact path escaped the store")
        return target

    @staticmethod
    def _verify_target(target: Path, ref: ArtifactRef) -> None:
        try:
            if target.is_symlink() or not target.is_file():
                raise ArtifactIntegrityError("artifact is missing or is not a regular file")
            payload = target.read_bytes()
        except OSError as exc:
            raise ArtifactIntegrityError("cannot verify artifact") from exc
        digest = hashlib.sha256(payload).hexdigest()
        if digest != ref.artifact_id.rsplit(":", 1)[1] or len(payload) != ref.size_bytes:
            raise ArtifactIntegrityError("artifact bytes do not match the content address")
