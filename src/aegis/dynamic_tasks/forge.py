"""Trusted TaskForge boundary built on the existing TaskPack validator."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from aegis.taskpacks.manifest import TaskPack
from aegis.taskpacks.validation import TaskPackRunner, validate_taskpack

from .models import DynamicTaskArtifact, DynamicTaskOrigin, DynamicTaskRecord
from .registry import DynamicTaskRegistry

MAX_DYNAMIC_TASK_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_DYNAMIC_TASK_FILES = 512
MAX_DYNAMIC_TASK_FILE_BYTES = 2 * 1024 * 1024


def _manifest_bytes(pack: TaskPack) -> bytes:
    manifest = pack.manifest
    value = {
        "task_id": manifest.task_id,
        "version": manifest.version,
        "language": manifest.language,
        "public_dir": manifest.public_dir,
        "hidden_dir": manifest.hidden_dir,
        "reference_dir": manifest.reference_dir,
        "defect_dir": manifest.defect_dir,
        "mutant_dirs": list(manifest.mutant_dirs),
        "content_hash": manifest.content_hash,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_taskpack_archive(pack: TaskPack) -> bytes:
    pack.verify_layout()
    pack.verify_integrity()
    files: list[tuple[str, bytes]] = []
    for path in sorted(pack.root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError("dynamic task packs must not contain symbolic links")
        if not path.is_file():
            continue
        relative = path.relative_to(pack.root).as_posix()
        content = _manifest_bytes(pack) if relative == "manifest.json" else path.read_bytes()
        files.append((relative, content))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative, content in files:
            info = tarfile.TarInfo(relative)
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    payload = output.getvalue()
    if not payload or len(payload) > MAX_DYNAMIC_TASK_ARCHIVE_BYTES:
        raise ValueError("dynamic task archive exceeds the size limit")
    return payload


def artifact_from_pack(pack: TaskPack, archive: bytes) -> DynamicTaskArtifact:
    digest = hashlib.sha256(archive).hexdigest()
    return DynamicTaskArtifact(
        artifact_id=f"dynamic-task-sha256:{digest}",
        task_id=pack.manifest.task_id,
        task_version=pack.manifest.version,
        language=pack.manifest.language,
        content_hash=pack.manifest.content_hash,
        archive_sha256=digest,
        size_bytes=len(archive),
    )


class TaskForge:
    """Materialize validation evidence and atomically bank the immutable pack."""

    def __init__(self, registry: DynamicTaskRegistry) -> None:
        self.registry = registry

    def forge(
        self,
        pack: TaskPack,
        runner: TaskPackRunner,
        *,
        creator_generation: int,
        source_spec_id: str,
        source_evidence_ids: tuple[str, ...],
        holdout_delay: int = 1,
        origin: DynamicTaskOrigin = DynamicTaskOrigin.DYNAMIC,
    ) -> DynamicTaskRecord:
        archive = canonical_taskpack_archive(pack)
        artifact = artifact_from_pack(pack, archive)
        report = validate_taskpack(pack, runner)
        return self.registry.register(
            artifact,
            archive,
            report,
            creator_generation=creator_generation,
            source_spec_id=source_spec_id,
            source_evidence_ids=source_evidence_ids,
            holdout_delay=holdout_delay,
            origin=origin,
        )

    def forge_archive(
        self,
        archive: bytes,
        runner: TaskPackRunner,
        *,
        creator_generation: int,
        source_spec_id: str,
        source_evidence_ids: tuple[str, ...],
        holdout_delay: int = 1,
    ) -> DynamicTaskRecord:
        """Validate a complete untrusted Judge archive in a temporary forge root."""
        if not isinstance(archive, bytes) or not archive:
            raise ValueError("task forge archive must be non-empty bytes")
        if len(archive) > MAX_DYNAMIC_TASK_ARCHIVE_BYTES:
            raise ValueError("task forge archive exceeds the compressed size limit")
        with tempfile.TemporaryDirectory(prefix="aegis-task-forge-") as directory:
            root = Path(directory).resolve(strict=True)
            self._extract_untrusted_archive(archive, root)
            pack = TaskPack.load(root)
            return self.forge(
                pack,
                runner,
                creator_generation=creator_generation,
                source_spec_id=source_spec_id,
                source_evidence_ids=source_evidence_ids,
                holdout_delay=holdout_delay,
                origin=DynamicTaskOrigin.DYNAMIC,
            )

    @staticmethod
    def _extract_untrusted_archive(archive: bytes, root: Path) -> None:
        try:
            stream = tarfile.open(fileobj=io.BytesIO(archive), mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            raise ValueError("task forge archive is not a valid tar archive") from exc
        seen: set[str] = set()
        total_size = 0
        with stream:
            members = stream.getmembers()
            if not members or len(members) > MAX_DYNAMIC_TASK_FILES:
                raise ValueError("task forge archive has an invalid file count")
            for member in members:
                if "\\" in member.name or any(ord(character) < 32 for character in member.name):
                    raise ValueError("task forge archive contains an unsafe path")
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                ):
                    raise ValueError("task forge archive contains an unsafe path")
                normalized = relative.as_posix()
                if normalized in seen:
                    raise ValueError("task forge archive contains duplicate members")
                seen.add(normalized)
                if not (member.isfile() or member.isdir()):
                    raise ValueError("task forge archive may contain only files and directories")
                if member.size < 0 or member.size > MAX_DYNAMIC_TASK_FILE_BYTES:
                    raise ValueError("task forge member exceeds the size limit")
                total_size += member.size
                if total_size > MAX_DYNAMIC_TASK_ARCHIVE_BYTES:
                    raise ValueError("task forge archive exceeds the expanded size limit")
                target = root.joinpath(*relative.parts)
                if target != root and root not in target.parents:
                    raise ValueError("task forge archive path escapes the forge root")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = stream.extractfile(member)
                if extracted is None:
                    raise ValueError("task forge file member has no content")
                payload = extracted.read(MAX_DYNAMIC_TASK_FILE_BYTES + 1)
                if len(payload) != member.size:
                    raise ValueError("task forge member size does not match content")
                try:
                    with target.open("xb") as output:
                        output.write(payload)
                except OSError as exc:
                    raise ValueError("cannot materialize task forge archive") from exc
