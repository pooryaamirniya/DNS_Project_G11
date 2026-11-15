# PatchGuard — Evidence-Based Security Patch Validation in CI/CD

**Sharif University of Technology · Data and Network Security · Project 1 · Group 11**

**Team:** Poorya Amirniya, Danial Azarnia, Mohammad Javad Khoshdouni Farahani, Mohammad Matin Ansari.

PatchGuard evaluates security patches to C/C++ Linux ELF targets using **actual program execution**, not variant filenames or a static-only scan. It compares baseline and candidate binaries, reproduces memory-safety failures with ASan/UBSan, checks expected functional behavior, correlates runtime findings with source differences, minimizes crashing inputs, preserves regression cases, inspects ELF hardening, and emits machine-readable verdicts for CI/CD.

> **Scope:** `PASS` means the declared security and functional tests passed for the evaluated versions and build conditions. It is **not** proof that a patch eliminates all vulnerabilities.

## Targets and provenance

The assessed six-scenario matrix uses two independent C targets:

| Target | Description | Source / validation |
|---|---|---|
| `frame` | Purpose-built message-frame parser containing a reproducible stack-buffer overflow. | `targets/frame/`, `docs/oracle-frame.md` |
| `cjsonreal` | Genuine upstream **cJSON** implementation using tags **v1.7.17** (vulnerable) and **v1.7.18** (patched), with a local stdin adapter for reproducible testing of **CVE-2024-31755** (`cJSON_SetValuestring`). | `targets/cjsonreal/`, `targets/cjsonreal/source_manifest.json`, `docs/oracle-cjsonreal.md` |

For each target, `base`, `correct`, `incomplete`, and `regression` variants are supplied. The `cjsonreal` incomplete and regression variants are **deliberately modified educational variants**, not officially published upstream releases. The old `targets/jsonc/` integration demonstration is retained for reference only and is **not** part of the assessed six-scenario matrix.

Original upstream cJSON copyrights and MIT license notices are preserved in `targets/cjsonreal/upstream/`. Provenance and SHA-256 hashes are recorded in `source_manifest.json`.

**Instructor approval:** Selection of the targets, test oracles, and agreed input scope requires instructor/TA confirmation. Approval has not been represented as obtained; see `docs/instructor-approval.md`.

## Prerequisites

- Linux **x86-64** (or WSL2 with Docker Desktop Linux containers).
- Docker with permission to run Linux containers, plus Python 3 for local test/assertion scripts.
- To run outside Docker, a **disposable** Linux VM or container with Python 3, GCC, binutils, git and `libjson-c-dev`. Running intentionally vulnerable binaries directly on an ordinary host is not recommended.

## Reproduce from a fresh checkout

```bash
git clone https://github.com/pooryaamirniya/DNS_Project_G11.git
cd DNS_Project_G11
bash tools/docker_run.sh
python3 -m unittest discover -s tests -v
python3 tools/blind_patch_test.py
python3 tools/quality_gate.py --strict
```

**Order matters:** the Docker matrix generates and persists minimized regression inputs. One unit test verifies the learned regression corpus, so on a **fresh checkout** the matrix should run **before** the unit suite. Both GitHub Actions workflows already follow this order.

The six-scenario Docker matrix asserts these verdicts:

| Scenario | Expected exit code |
|---|---:|
| `frame-correct` | 0 |
| `frame-incomplete` | 10 |
| `frame-regression` | 20 |
| `cjsonreal-correct` | 0 |
| `cjsonreal-incomplete` | 10 |
| `cjsonreal-regression` | 20 |

The **overall** mixed batch can report `FUNC_REGRESSION (20)` because it intentionally includes negative fixtures. `Scenario matrix PASS` means all **individual expected verdicts** matched, and `tools/docker_run.sh` exits successfully. For the blind suite, the expected outcome is `Blind patch matrix: 9/9 passed`; for evidence auditing, `Quality Gate: PASS` with no errors or warnings. Negative unit tests may print an expected `Quality Gate: FAIL` message while the test itself reports `ok`.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | `PASS` — the declared checks succeeded. |
| `10` | `VULN_REMAINS_OR_NEW_ISSUE` — a validated security defect persists or another confirmed issue was observed. |
| `20` | `FUNC_REGRESSION` — an independent functional oracle detects regression. |
| `30` | `BUILD_OR_CONFIG_ERROR` — build, configuration or environment failure. |
| `40` | `INCONCLUSIVE` — required evidence is missing, conflicting or unstable. |

The structured report also distinguishes `security_status` (e.g., `fixed`, `incomplete`, `new_issue`) from `functionality_status` and `analysis_complete`. A code of 10 alone does not conflate a retained flaw with a new one.

## Evaluate an unseen candidate

Place a compatible candidate `.c` file **inside the checkout** and run, for example:

```bash
python3 tools/evaluate_candidate.py --target frame --source candidate_sources/changed.c
```

Or use `--target cjsonreal` for a compatible cJSON test-adapter source file. The command does not modify the PatchGuard decision logic based on filename. It may legitimately exit with 0, 10, 20, 30 or 40; a nonzero verdict is **not** by itself a tool malfunction. Run all intentionally unsafe binaries using the provided isolated Docker tools.

## Reports and evidence

- `artifacts/ci/report.json`, `artifacts/ci/report.md` — detailed six-scenario evaluation.
- `artifacts/ci/repro/`, `artifacts/ci/regression/` — reproducible inputs, minimization metadata and replay details.
- `regressions/<target>/` — persisted, learned regression inputs for later evaluations.
- `artifacts/blind-patches/manifest.json`, `artifacts/blind-patches/summary.json` — nine generated candidate tests.
- `artifacts/quality-gate/quality_report.{json,md}` — independent evidence and provenance checks.
- `.github/workflows/patchguard.yml`, `.github/workflows/quality-gate.yml` — automated GitHub Actions validation.

Generated artifacts may contain **historical** run IDs and machine-specific paths. For an authoritative fresh-run result, use the current GitHub Actions execution and its downloadable artifacts or rerun the commands above from a clean checkout.

## Architecture and limitations

- `patchguard/runner.py` — compiler/runtime execution and build variants.
- `patchguard/detection.py` — sanitizer parsing, application-frame selection and error signatures.
- `patchguard/correlation.py` — runtime finding to source-diff evidence correlation.
- `patchguard/minimize.py` — crash-preserving input minimization.
- `patchguard/hardening.py` — ELF mitigation inspection.
- `patchguard/cli.py` — verdicts, reproducible artifacts and report generation.
- `configs/*.json` — target paths, input modes, attack/functional cases, expected behavior and build options.
- `tests/` — logic and regression unit tests.

A function overlap in a diff and stack trace is **correlation evidence, not proof of causation**. Sanitizer coverage is finite; unknown patches and environment differences can require further tests or an `INCONCLUSIVE` result. See `docs/architecture.md` for details.

## Defense and handover

See `README_FA.md` for Persian quick-start, `docs/FINAL_SUBMISSION_CHECKLIST_FA.md` for delivery verification, and `docs/TEAM_CONTRIBUTIONS_TEMPLATE_FA.md` for a record of each member's **actual** contributions. The instructor requires individual understanding, hands-on changes and an independent defense; do not assign fictitious work or claim unrecorded instructor approval.
