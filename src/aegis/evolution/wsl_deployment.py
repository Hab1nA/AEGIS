"""Host-side doctor for the dedicated WSL evolution volume and agents."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Mapping
from typing import Any, cast

from aegis.models import canonical_json
from aegis.sandbox.types import DoctorCheck, DoctorReport

_SAFE_DISTRIBUTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_MAX_RESPONSE_BYTES = 65_536
DoctorTransport = Callable[[float], Mapping[str, Any]]


class WslEvolutionDeploymentError(RuntimeError):
    pass


class WslEvolutionDeployment:
    """Verify immutable agent locations and the bounded non-DrvFS state volume."""

    def __init__(
        self,
        distribution: str = "AEGIS-Sandbox",
        *,
        doctor_path: str = "/usr/local/bin/aegis-evolution-doctor",
        transport: DoctorTransport | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if _SAFE_DISTRIBUTION.fullmatch(distribution) is None:
            raise ValueError("unsafe WSL distribution name")
        if doctor_path != "/usr/local/bin/aegis-evolution-doctor":
            raise ValueError("evolution doctor path is fixed by the host safety envelope")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be in [1, 120]")
        self.distribution = distribution
        self.doctor_path = doctor_path
        self._transport = transport or self._wsl_transport
        self._timeout = float(timeout_seconds)

    def transport_argv(self) -> tuple[str, ...]:
        return (
            "wsl.exe",
            "--distribution",
            self.distribution,
            "--",
            self.doctor_path,
        )

    def doctor(self) -> DoctorReport:
        response = self._transport(self._timeout)
        if not isinstance(response, Mapping) or response.get("ok") is not True:
            raise WslEvolutionDeploymentError(
                str(response.get("message", "evolution doctor failed"))[:1024]
                if isinstance(response, Mapping)
                else "evolution doctor response must be an object"
            )
        raw = response.get("checks")
        if not isinstance(raw, list) or not raw:
            raise WslEvolutionDeploymentError("evolution doctor omitted checks")
        checks: list[DoctorCheck] = []
        expected = {
            "fixed_agents",
            "source_mirror",
            "campaign_volume_ext4",
            "campaign_volume_bounded",
            "windows_mounts_disabled",
            "interop_disabled",
        }
        for item in raw:
            if not isinstance(item, Mapping) or set(item) != {"name", "passed", "detail"}:
                raise WslEvolutionDeploymentError("evolution doctor check is malformed")
            name = item["name"]
            passed = item["passed"]
            detail = item["detail"]
            if (
                not isinstance(name, str)
                or name not in expected
                or not isinstance(passed, bool)
                or not isinstance(detail, str)
                or len(detail.encode("utf-8")) > 2048
            ):
                raise WslEvolutionDeploymentError("evolution doctor check is invalid")
            checks.append(DoctorCheck(name, passed, detail))
        if {check.name for check in checks} != expected or len(checks) != len(expected):
            raise WslEvolutionDeploymentError("evolution doctor checks are incomplete or duplicated")
        return DoctorReport(tuple(checks))

    def _wsl_transport(self, timeout: float) -> Mapping[str, Any]:
        try:
            result = subprocess.run(
                self.transport_argv(),
                input="",
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WslEvolutionDeploymentError(f"WSL evolution doctor failed: {exc}") from exc
        if len(result.stdout.encode("utf-8", errors="replace")) > _MAX_RESPONSE_BYTES:
            raise WslEvolutionDeploymentError("evolution doctor response exceeded limit")
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise WslEvolutionDeploymentError("evolution doctor returned invalid JSON") from exc
        if not isinstance(decoded, Mapping):
            raise WslEvolutionDeploymentError("evolution doctor response must be an object")
        # Round-trip through canonical JSON so custom Mapping implementations
        # cannot retain executable behavior beyond this trust boundary.
        return cast(Mapping[str, Any], json.loads(canonical_json(decoded)))
