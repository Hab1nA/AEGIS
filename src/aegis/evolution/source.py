"""Secret-free source bindings for the WSL harness campaign mirror."""

from __future__ import annotations

from urllib.parse import urlsplit

SOURCE_MIRROR_PATH = "/var/lib/aegis/source-mirror.git"
SOURCE_MIRROR_URL = "file://" + SOURCE_MIRROR_PATH


def is_local_source_mirror(value: str) -> bool:
    """True only for the exact immutable WSL mirror source."""
    if not isinstance(value, str) or "\x00" in value:
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme == "file"
        and parsed.netloc == ""
        and parsed.path == SOURCE_MIRROR_PATH
        and not parsed.query
        and not parsed.fragment
        and "\\" not in value
    )
