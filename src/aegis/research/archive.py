"""Defensive, extraction-free validation of ZIP and TAR archives."""

from __future__ import annotations

import io
import posixpath
import tarfile
import zipfile
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_entries: int = 10_000
    max_expanded_bytes: int = 256 * 1024 * 1024
    max_single_file_bytes: int = 64 * 1024 * 1024
    max_compression_ratio: float = 100.0


def _validate_member(name: str, size: int, compressed_size: int, limits: ArchiveLimits) -> None:
    normalized = name.replace("\\", "/")
    drive_prefix = len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha()
    if (
        not normalized
        or normalized.startswith("/")
        or drive_prefix
        or "\x00" in normalized
        or ".." in normalized.split("/")
        or posixpath.normpath(normalized).startswith("../")
    ):
        raise ValueError(f"unsafe archive path: {name!r}")
    if size < 0 or size > limits.max_single_file_bytes:
        raise ValueError("archive member exceeds size limit")
    if size and compressed_size <= 0:
        raise ValueError("archive member has invalid compressed size")
    if compressed_size and size / compressed_size > limits.max_compression_ratio:
        raise ValueError("archive member exceeds compression ratio limit")


def validate_archive(data: bytes, limits: ArchiveLimits = ArchiveLimits()) -> tuple[str, ...]:
    """Validate archive metadata without extracting any content."""
    stream = io.BytesIO(data)
    names: list[str] = []
    expanded = 0
    if zipfile.is_zipfile(stream):
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_entries:
                raise ValueError("archive has too many entries")
            for info in infos:
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise ValueError("archive symlinks are not allowed")
                _validate_member(info.filename, info.file_size, info.compress_size, limits)
                expanded += info.file_size
                names.append(info.filename)
    else:
        stream.seek(0)
        try:
            tar_archive = tarfile.open(fileobj=stream, mode="r:*")
        except tarfile.TarError as exc:
            raise ValueError("unsupported or invalid archive") from exc
        with tar_archive:
            members = tar_archive.getmembers()
            if len(members) > limits.max_entries:
                raise ValueError("archive has too many entries")
            for member in members:
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError("archive links and special files are not allowed")
                _validate_member(member.name, member.size, member.size, limits)
                expanded += member.size
                names.append(member.name)
    if expanded > limits.max_expanded_bytes:
        raise ValueError("archive exceeds total expanded size limit")
    if data and expanded / len(data) > limits.max_compression_ratio:
        raise ValueError("archive exceeds aggregate compression ratio limit")
    return tuple(names)
