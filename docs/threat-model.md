# Threat model

## Protected assets

- Windows files, credentials, processes, network services, and user sessions.
- Hidden tests, references, mutants, scoring rules, budgets, and promotion state.
- Audit-event integrity and accurate token attribution.

## Adversaries

Warrior, Judge, Prosecutor, downloaded web content, task code, dependencies, and model output are all untrusted. Prompt injection and malicious task code are expected, not exceptional.

## Enforced controls

- Dedicated WSL distribution with Windows automount, interop, and Windows PATH injection disabled.
- Rootless Podman, no task network, no capabilities, bounded CPU/memory/PIDs, and no container socket or host secrets.
- Dedicated 67,108,864-byte loopback ext4 workspace. Startup verifies the kernel mount table and `statvfs`; a marker alone never proves isolation.
- Strict JSON action schemas, role-specific tool permissions, safe relative paths, bounded I/O, immutable freeze hashes, and independent hidden evaluation.
- Request capacity reserved before transport; actual usage is committed or the reservation is released. Production fake sandboxes and unconfigured online research fail closed.
- Killing the local WSL client is not considered container cleanup. The WSL agent explicitly runs rootless `podman rm --force --time 0` for both the main and sealed evaluator container names on timeout, bounded-output failure, abnormal execution, stop, and kill. Missing containers are idempotent; other Podman cleanup failures remain durable campaign failures.

## Enforced controls (WSL-first, 2026-09-14)

- Gateway credentials live only in the fixed in-distro sidecar process; the
  champion executor sees a loopback URL, never a key.  The sidecar pins the
  upstream to SSRF-validated addresses (rebinding-safe) and meters every
  request to a JSONL ledger the host reconciles after each cycle.
- The supervisor launches exactly `refs/aegis/champion`: Tier 1 probe with
  namespace isolation and tiny rlimits, Tier 2 detached executor with
  generous but bounded rlimits and no credential environment.
- The harness agent byte-compares every candidate/rollback tree against the
  campaign's pinned source ref: changed paths must fall inside the evolvable
  harness grant, so frozen files stay frozen even though the whole tree is
  what executes.

## Residual risk

WSL2 is not equivalent to a separately administered remote machine. Hypervisor, kernel, Podman, filesystem, and WSL integration defects remain possible. The bootstrap renderer only stages configuration beneath an explicitly selected root; an operator must install it in a dedicated distribution, enable the service, and verify the independent mount. High-value or hostile workloads should use a disposable Hyper-V or remote VM backend.
