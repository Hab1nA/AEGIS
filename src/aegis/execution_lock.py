"""Cross-process, crash-released campaign execution ownership."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO


class CampaignAlreadyRunningError(RuntimeError):
    """Another live process owns the campaign execution lock."""


class CampaignExecutionLock:
    """A non-blocking OS file lock; the kernel releases it on process death."""

    def __init__(self, data_path: Path, campaign_id: str) -> None:
        digest = hashlib.sha256(campaign_id.encode("utf-8")).hexdigest()[:24]
        self.path = data_path.parent / "locks" / f"campaign-{digest}.lock"
        self._handle: BinaryIO | None = None

    def __enter__(self) -> "CampaignExecutionLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl: Any = __import__("fcntl")

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise CampaignAlreadyRunningError(
                "campaign is already running in another process; pause it or wait for owner exit"
            ) from exc
        self._handle = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl: Any = __import__("fcntl")

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
