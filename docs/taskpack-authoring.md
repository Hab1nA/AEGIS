# Task-pack authoring

Each Python pack contains `manifest.json`, `prompt.md`, defect and reference implementations, a public pytest suite, a sealed hidden `cases.json` suite, and at least one anti-hacking mutant. Executable hidden Python suites are rejected. Paths must be distinct, relative, symlink-free directories. The manifest `content_hash` covers every pack file except the manifest itself. See [sealed hidden tests v1](sealed-hidden-tests-v1.md) for the DSL contract.

Validation evidence is stored adjacent to the pack as `<pack-directory-name>.validation.json`, because embedding a file containing the pack hash inside the hashed tree would be self-referential. Evidence names the same `content_hash` and records strict `ExecutionResult` objects for reference/public, reference/hidden, defect/public, defect/hidden, and every mutant/hidden run.

At real startup AEGIS does not trust that evidence alone. `SandboxTaskPackRunner` reruns every implementation/suite pair in a fresh sandbox. Public tests use pytest; hidden cases use the trusted sealed evaluator and black-box worker. The reference must pass non-empty public and hidden suites; the defect must be detected; every mutant must be killed; live pass status and test counts must match the sealed evidence. Failure aborts before a campaign starts.

Only `prompt.md`, the defect implementation, and public tests may enter the Warrior workspace. Sealed cases, references, and mutants remain controller-side and never enter the Warrior or submission-worker filesystem. Keep tasks small enough to run in minutes while targeting common AI failures: edge conditions, state leakage, concurrency, unsafe path handling, contract preservation, and tests that reject hard-coded answers.
